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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches the signing public key of a creator from the well known end point
 * on the domain the OWID carries, asking for the key that was in force on the
 * date the OWID carries.
 *
 * <p>The end point is
 * {@code /owid/api/v{n}/public-key?date={minutes}&amp;format=pkcs}, where the
 * version in the path is the version byte of the OWID being checked rather
 * than a constant, and the minutes are counted from 2020-01-01 in the same
 * way the OWID stores the date. Creators rotate weekly, so without the date
 * only identifiers signed since the most recent rotation can be verified and
 * every older one reads as not matching. A creator that ignores the
 * parameter returns its current key, so every identifier it signed under an
 * earlier key reads as not matching, which is why a creator that rotates its
 * key has to honour the date.</p>
 *
 * <p>Every method here that reaches the network answers with a
 * {@link CompletableFuture} and returns at once. There is no form that
 * waits, so a request thread or an event loop is never held while a creator
 * answers, and a caller that wants to wait joins the future itself. The
 * request is made by a {@link PublicKeyTransport}, and where the caller
 * names none {@link HttpUrlConnectionTransport} is used, which runs the
 * JDK's blocking connection on a background thread. On Java 11 and later a
 * caller can supply a transport over
 * {@code java.net.http.HttpClient.sendAsync} instead, which blocks no thread
 * at all. Building the URL is pure text and reaches nothing, so
 * {@link #publicKeyUrl(Owid, String)} answers in the ordinary way.</p>
 *
 * <p>Only the JDK is used, so the library keeps its promise of no runtime
 * dependencies and still runs on Java 8, which has no HTTP client of its
 * own.</p>
 *
 * <p>The Rust port answers the same question with {@code Owid::verify_status}
 * and the Go port with {@code SignatureStatusFromDomain}.</p>
 */
public final class PublicKeyFetch {

    /**
     * The most keys held in the cache before the cache is emptied and filled
     * again. A bound is needed because a verifier sees identifiers from many
     * domains and many weeks, and an unbounded map would grow for as long as
     * the process runs.
     */
    private static final int MAXIMUM_CACHED_KEYS = 1024;

    /**
     * Keys fetched, or on their way, held against the URL they were asked
     * for.
     *
     * <p>The specification asks implementations to cache so that verifying
     * many identifiers does not mean repeating requests to another
     * processor. Holding the key against the whole URL is safe because the
     * URL names the domain, the version and the minute, and the key a
     * creator published for a minute in the past does not change.</p>
     *
     * <p>The value is the future of the fetch rather than the key itself, so
     * a second request for a key that is still on its way joins the request
     * already made instead of making another. A fetch that fails is removed
     * the moment it fails, so an outage is never remembered and the next
     * request tries again.</p>
     */
    private static final Map<String, CompletableFuture<String>> CACHE =
            new ConcurrentHashMap<String, CompletableFuture<String>>();

    /** The transport used where the caller names none. */
    private static final PublicKeyTransport DEFAULT_TRANSPORT =
            new HttpUrlConnectionTransport();

    private PublicKeyFetch() {
    }

    /**
     * Returns the URL of the public key end point for the OWID, using the
     * scheme provided, which is normally {@code https}.
     *
     * <p>The date the OWID carries is sent as the {@code date} parameter,
     * counted in whole minutes from 2020-01-01, so that a creator which
     * rotates its key returns the key that was in force when this OWID was
     * signed. The parameter is left out where the date cannot be counted,
     * which no OWID this library reads can be, because the wire format
     * cannot hold such a date.</p>
     *
     * @param owid   the OWID whose creator key is wanted
     * @param scheme the scheme to use, normally {@code https}
     * @return the URL of the public key end point
     * @throws OwidException if the OWID or the scheme is missing, or the
     *                       domain the OWID carries is not a domain this
     *                       library will put in a URL
     */
    public static String publicKeyUrl(Owid owid, String scheme)
            throws OwidException {
        if (owid == null) {
            throw new OwidException("the OWID is missing");
        }
        if (scheme == null || scheme.trim().isEmpty()) {
            throw new OwidException("the scheme is missing");
        }
        String domain = owid.getDomain();
        checkDomain(domain);
        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(domain)
                .append(Endpoints.publicKeyPath(owid.getVersion()));
        long minutes = Io.minutesSinceBase(owid.getDate());
        url.append('?');
        if (minutes >= 0) {
            url.append("date=").append(minutes).append('&');
        }
        url.append("format=pkcs");
        return url.toString();
    }

    /**
     * Fetches the public key PEM of the creator of the OWID, for the date
     * the OWID carries, using {@link HttpUrlConnectionTransport} on its
     * shared pool.
     *
     * <p>Returns at once. The future completes with the key in PEM form,
     * fails with a {@link PublicKeyFetchException} where the key could not
     * be obtained, carrying the status to report for the identifier, and
     * fails with an {@link OwidException} where the OWID, the scheme or the
     * domain is not usable. Nothing is thrown from the call itself.</p>
     *
     * @param owid   the OWID whose creator key is wanted
     * @param scheme the scheme to use, normally {@code https}
     * @return the public key in PEM form, through a future
     */
    public static CompletableFuture<String> publicKeyPem(Owid owid,
            String scheme) {
        return publicKeyPem(owid, scheme, DEFAULT_TRANSPORT);
    }

    /**
     * Fetches the public key PEM of the creator of the OWID, for the date
     * the OWID carries, using the transport given.
     *
     * <p>Returns at once. The future completes with the key in PEM form,
     * fails with a {@link PublicKeyFetchException} where the key could not
     * be obtained, carrying the status to report for the identifier, and
     * fails with an {@link OwidException} where the OWID, the scheme, the
     * domain or the transport is not usable. Nothing is thrown from the
     * call itself.</p>
     *
     * @param owid      the OWID whose creator key is wanted
     * @param scheme    the scheme to use, normally {@code https}
     * @param transport the transport to make the request with
     * @return the public key in PEM form, through a future
     */
    public static CompletableFuture<String> publicKeyPem(Owid owid,
            String scheme, PublicKeyTransport transport) {
        String url;
        try {
            url = publicKeyUrl(owid, scheme);
        } catch (OwidException e) {
            return failed(e);
        }
        return publicKeyPemAtUrl(url, owid.getDomain(), transport);
    }

    /**
     * Asks whether the signature on the OWID is genuine, fetching the key
     * that was in force when the OWID was signed from the creator domain
     * using {@link HttpUrlConnectionTransport} on its shared pool.
     *
     * <p>Returns at once, and the future never fails, because every route
     * out of the fetch promises a status. A key that cannot be fetched is
     * {@link OwidSignatureStatus#KEY_UNAVAILABLE} and one that arrives in a
     * form this library cannot read is
     * {@link OwidSignatureStatus#INVALID_KEY}. Neither is
     * {@link OwidSignatureStatus#SIGNATURE_INVALID}, because an outage or a
     * badly served key leaves the signature unjudged, and reporting either
     * as invalid would read as an attack. The signature is examined on the
     * thread that completes the fetch, which for the default transport is
     * one of its pool, or on the caller's own thread where the key is
     * already held.</p>
     *
     * @param owid   the OWID to check
     * @param scheme the scheme to use, normally {@code https}
     * @param others the other OWIDs that were signed together with this one,
     *               in the same order as when signed
     * @return the outcome of the check, through a future
     */
    public static CompletableFuture<OwidVerificationResult> verify(Owid owid,
            String scheme, List<Owid> others) {
        return verify(owid, scheme, others, DEFAULT_TRANSPORT);
    }

    /**
     * Asks whether the signature on the OWID is genuine, fetching the key
     * that was in force when the OWID was signed from the creator domain
     * using the transport given.
     *
     * <p>Returns at once, and the future never fails, because every route
     * out of the fetch promises a status. A key that cannot be fetched, a
     * URL that cannot be built and a transport that is missing are all
     * {@link OwidSignatureStatus#KEY_UNAVAILABLE}, and a key that arrives in
     * a form this library cannot read is
     * {@link OwidSignatureStatus#INVALID_KEY}. Neither is
     * {@link OwidSignatureStatus#SIGNATURE_INVALID}, because an outage or a
     * badly served key leaves the signature unjudged, and reporting either
     * as invalid would read as an attack. The signature is examined on the
     * thread that completes the fetch, or on the caller's own thread where
     * the key is already held.</p>
     *
     * @param owid      the OWID to check
     * @param scheme    the scheme to use, normally {@code https}
     * @param others    the other OWIDs that were signed together with this
     *                  one, in the same order as when signed
     * @param transport the transport to make the request with
     * @return the outcome of the check, through a future
     */
    public static CompletableFuture<OwidVerificationResult> verify(Owid owid,
            String scheme, List<Owid> others, PublicKeyTransport transport) {
        String url;
        try {
            url = publicKeyUrl(owid, scheme);
        } catch (OwidException e) {
            return CompletableFuture.completedFuture(
                    OwidVerificationResult.of(
                            OwidSignatureStatus.KEY_UNAVAILABLE));
        }
        return verifyAtUrl(owid, url, others, transport);
    }

    /**
     * Empties the cache of keys already fetched. Provided so that a long
     * running process can release the memory, and so that a test can start
     * from a known state. A fetch still on its way is forgotten here but
     * still completes for whoever holds its future.
     */
    public static void clearCache() {
        CACHE.clear();
    }

    /**
     * The work {@link #verify(Owid, String, List, PublicKeyTransport)} does
     * once the URL is known, kept apart so that the tests drive the real
     * fetch against a key end point the tests can stand up locally rather
     * than against a near copy of the fetch.
     */
    static CompletableFuture<OwidVerificationResult> verifyAtUrl(
            final Owid owid, String url, final List<Owid> others,
            PublicKeyTransport transport) {
        return publicKeyPemAtUrl(url, owid.getDomain(), transport)
                .handle((pem, failure) -> {
                    if (failure != null) {
                        return OwidVerificationResult.of(statusOf(failure));
                    }
                    return owid.verify(pem, others);
                });
    }

    /**
     * Fetches the PEM at the URL, answering from the cache where the same
     * URL has already been fetched or is being fetched now.
     *
     * <p>The future held in the cache is this class's own rather than the
     * transport's, so that the transport's completion can be watched and a
     * failure dropped from the cache without touching the map from inside
     * one of its own operations, which a concurrent map does not allow.</p>
     */
    static CompletableFuture<String> publicKeyPemAtUrl(final String url,
            String domain, PublicKeyTransport transport) {
        if (transport == null) {
            return failed(new OwidException("the transport is missing"));
        }
        CompletableFuture<String> held = CACHE.get(url);
        if (held != null) {
            return held;
        }
        if (CACHE.size() >= MAXIMUM_CACHED_KEYS) {
            CACHE.clear();
        }
        final CompletableFuture<String> fetch = new CompletableFuture<String>();
        held = CACHE.putIfAbsent(url, fetch);
        if (held != null) {
            // Another thread asked for the same key between the lookup and
            // the insert, and its fetch is the one both callers share.
            return held;
        }
        CompletableFuture<String> started;
        try {
            started = transport.fetch(url, domain);
        } catch (RuntimeException e) {
            // A transport keeps its promise by failing the future rather
            // than throwing, but one that breaks the promise must not leave
            // a future in the cache that never completes.
            started = failed(e);
        }
        if (started == null) {
            started = failed(new PublicKeyFetchException(
                    "the transport returned no future for domain '" + domain
                            + "'",
                    OwidSignatureStatus.KEY_UNAVAILABLE, domain, 0, null));
        }
        started.whenComplete((pem, failure) -> {
            if (failure == null && pem != null) {
                fetch.complete(pem);
                return;
            }
            // Only this fetch is removed, never whatever replaced it after
            // the cache was emptied and filled again in the meantime.
            CACHE.remove(url, fetch);
            fetch.completeExceptionally(failure != null
                    ? unwrap(failure)
                    : new PublicKeyFetchException(
                            "the transport returned no key for domain '"
                                    + domain + "'",
                            OwidSignatureStatus.KEY_UNAVAILABLE, domain, 0,
                            null));
        });
        return fetch;
    }

    /** A future that has already failed with the exception given. */
    private static <T> CompletableFuture<T> failed(Throwable failure) {
        CompletableFuture<T> future = new CompletableFuture<T>();
        future.completeExceptionally(failure);
        return future;
    }

    /**
     * The exception a failed future carries, with the wrapper a dependent
     * future adds taken off so the one the transport raised is what a
     * caller sees.
     */
    private static Throwable unwrap(Throwable failure) {
        Throwable cause = failure;
        while (cause instanceof CompletionException
                && cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    /**
     * The status to report for a fetch that failed. A fetch failure carries
     * its own status, and anything else, such as a URL that could not be
     * built, means the key was never obtained.
     */
    private static OwidSignatureStatus statusOf(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause instanceof PublicKeyFetchException) {
            return ((PublicKeyFetchException) cause).getStatus();
        }
        return OwidSignatureStatus.KEY_UNAVAILABLE;
    }

    /**
     * Refuses a domain that would change the shape of the URL rather than
     * name a host in it.
     *
     * <p>The domain arrives inside an OWID, which came from outside, so the
     * text is not the library's own. Letters, digits, dots and hyphens are
     * all a domain name needs, and anything else could add a query, a
     * fragment, a port, credentials or a path and send the request somewhere
     * other than the creator.</p>
     */
    private static void checkDomain(String domain) throws OwidException {
        if (domain == null || domain.isEmpty()) {
            throw new OwidException("the OWID carries no domain");
        }
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '-';
            if (allowed == false) {
                // The domain is not repeated back, because the text arrived
                // from outside and a refusal is often logged.
                throw new OwidException(
                        "the domain in the OWID is not a domain name this "
                                + "library will request a key from");
            }
        }
    }
}
