/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

package com.swancommunity.owid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The transport used where a caller names none, making the request with
 * {@link HttpURLConnection} from the JDK.
 *
 * <p>HttpURLConnection blocks the thread that calls it, so the request is
 * handed to an {@link Executor} and the future returned completes when the
 * thread the executor gave it has the response. The thread that asked is
 * never held. That is blocking I/O on a background thread, which is the
 * best Java 8 offers without a dependency. On Java 11 and later supply a
 * {@link PublicKeyTransport} of your own over
 * {@code java.net.http.HttpClient.sendAsync} instead, which blocks no
 * thread at all, and keep the two rules that interface describes.</p>
 *
 * <p>Where no executor is given a pool shared by every instance is used. Its
 * threads are daemon threads, so a process that is otherwise finished is not
 * kept alive by a fetch still in flight, and there are never more of them
 * than twice the processors available, with at least two. Requests beyond
 * that wait in a queue rather than being refused, and a thread that has had
 * nothing to do for a minute ends.</p>
 *
 * <p>Only the JDK is used, so the library keeps its promise of no runtime
 * dependencies.</p>
 */
public final class HttpUrlConnectionTransport implements PublicKeyTransport {

    /** How long to wait for the connection to be made, in milliseconds. */
    private static final int CONNECT_TIMEOUT_MILLISECONDS = 5000;

    /** How long to wait for the response, in milliseconds. */
    private static final int READ_TIMEOUT_MILLISECONDS = 10000;

    /** How long an idle thread of the shared pool lives, in seconds. */
    private static final long IDLE_THREAD_SECONDS = 60;

    /** The executor the blocking request is handed to. */
    private final Executor executor;

    /**
     * Creates a transport that runs each request on the shared pool of
     * daemon threads described in the class comment.
     */
    public HttpUrlConnectionTransport() {
        this(SharedPool.INSTANCE);
    }

    /**
     * Creates a transport that runs each request on the executor given.
     *
     * <p>The executor is the caller's own, so its threads, their number and
     * whether they are daemon threads are the caller's choice, and ending
     * it when the process ends is the caller's job too.</p>
     *
     * @param executor the executor to run each request on
     * @throws IllegalArgumentException if the executor is missing
     */
    public HttpUrlConnectionTransport(Executor executor) {
        if (executor == null) {
            throw new IllegalArgumentException("the executor is missing");
        }
        this.executor = executor;
    }

    @Override
    public CompletableFuture<String> fetch(final String url,
            final String domain) {
        final CompletableFuture<String> future =
                new CompletableFuture<String>();
        try {
            executor.execute(() -> {
                try {
                    future.complete(read(url, domain));
                } catch (PublicKeyFetchException e) {
                    future.completeExceptionally(e);
                } catch (Throwable e) {
                    // Nothing in read is expected to throw anything else,
                    // but a future that is never completed would hold a
                    // caller for ever, so whatever escaped is carried out
                    // as the key being unavailable. An Error is then
                    // rethrown, because the thread it happened on has to
                    // know as well.
                    future.completeExceptionally(unexpected(domain, e));
                    if (e instanceof Error) {
                        throw (Error) e;
                    }
                }
            });
        } catch (RejectedExecutionException e) {
            // An executor that has been shut down, or one with a bounded
            // queue that is full, refuses the task at once. The refusal
            // arrives through the future like every other failure, so a
            // caller has one place to look.
            future.completeExceptionally(new PublicKeyFetchException(
                    "the request for the public key of domain "
                            + quoted(domain)
                            + " was refused by the executor",
                    OwidSignatureStatus.KEY_UNAVAILABLE,
                    domain,
                    0,
                    e));
        }
        return future;
    }

    /** Performs the request and returns the body as text. */
    private static String read(String url, String domain)
            throws PublicKeyFetchException {
        HttpURLConnection connection = null;
        try {
            // URI then toURL rather than the URL(String) constructor,
            // which is deprecated from Java 20 and would fail a consumer
            // compiling this source with warnings as errors.
            URLConnection opened = new URI(url).toURL().openConnection();
            if ((opened instanceof HttpURLConnection) == false) {
                // A scheme the caller chose that does not make an HTTP
                // request, such as file. Reported as a key that could not be
                // obtained rather than allowed to escape as a cast failure,
                // because every route into this class promises a status.
                throw new PublicKeyFetchException(
                        "the scheme used for domain " + quoted(domain)
                                + " does not make an HTTP request",
                        OwidSignatureStatus.KEY_UNAVAILABLE,
                        domain,
                        0,
                        null);
            }
            connection = (HttpURLConnection) opened;
            // Never follow a redirect. HttpURLConnection follows one to
            // any other host by default, so a creator whose domain
            // answered 302 to some other place would have that other
            // place's key trusted as its own, and a network attacker able
            // to bend the creator's DNS, or a creator that was simply
            // misconfigured, could put a key there and have forgeries
            // verify. Left alone, the 3xx is the response code, and the
            // check below reads it as the key being unavailable, which it
            // is.
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLISECONDS);
            connection.setReadTimeout(READ_TIMEOUT_MILLISECONDS);
            connection.setRequestProperty("Accept", "text/plain");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                drain(connection.getErrorStream());
                throw new PublicKeyFetchException(
                        "domain " + quoted(domain) + " returned code '" + code
                                + "' for the public key",
                        OwidSignatureStatus.KEY_UNAVAILABLE,
                        domain,
                        code,
                        null);
            }
            InputStream body = connection.getInputStream();
            try {
                return new String(readAll(body), StandardCharsets.UTF_8);
            } finally {
                body.close();
            }
        } catch (IOException | URISyntaxException e) {
            // A refused connection, a name that does not resolve, a
            // timeout and a url that will not parse all arrive here, and
            // all of them mean the signature was never examined.
            throw new PublicKeyFetchException(
                    "the public key could not be fetched from domain "
                            + quoted(domain),
                    OwidSignatureStatus.KEY_UNAVAILABLE,
                    domain,
                    0,
                    e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** The failure to carry for something read was not expected to throw. */
    private static PublicKeyFetchException unexpected(String domain,
            Throwable cause) {
        return new PublicKeyFetchException(
                "the request for the public key of domain " + quoted(domain)
                        + " failed unexpectedly",
                OwidSignatureStatus.KEY_UNAVAILABLE,
                domain,
                0,
                cause);
    }

    /** The value in single quotes, for a message. */
    private static String quoted(String value) {
        return "'" + value + "'";
    }

    /** Reads a stream to its end. */
    private static byte[] readAll(InputStream stream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] block = new byte[4096];
        int read = stream.read(block);
        while (read > 0) {
            buffer.write(block, 0, read);
            read = stream.read(block);
        }
        return buffer.toByteArray();
    }

    /** Closes the error body of a refused request, where there is one. */
    private static void drain(InputStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.close();
        } catch (IOException e) {
            // Nothing useful can be done about a body that will not close,
            // and the refusal itself is what the caller is told about.
        }
    }

    /**
     * The pool shared by every transport created without an executor. The
     * pool starts no thread until a request is handed to it, so a process
     * that only ever verifies with keys it already holds starts none.
     */
    private static final class SharedPool {

        static final Executor INSTANCE = create();

        private SharedPool() {
        }

        private static Executor create() {
            int threads = Math.max(2,
                    Runtime.getRuntime().availableProcessors() * 2);
            ThreadPoolExecutor pool = new ThreadPoolExecutor(threads, threads,
                    IDLE_THREAD_SECONDS, TimeUnit.SECONDS,
                    new LinkedBlockingQueue<Runnable>(),
                    new ThreadFactory() {
                        private final AtomicInteger made = new AtomicInteger();

                        @Override
                        public Thread newThread(Runnable task) {
                            Thread thread = new Thread(task,
                                    "owid-public-key-fetch-"
                                            + made.incrementAndGet());
                            thread.setDaemon(true);
                            return thread;
                        }
                    });
            // Core threads are the whole pool, so without this they would
            // live for ever once started.
            pool.allowCoreThreadTimeOut(true);
            return pool;
        }
    }
}
