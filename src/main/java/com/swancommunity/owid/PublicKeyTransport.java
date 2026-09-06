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

import java.util.concurrent.CompletableFuture;

/**
 * Makes the request for a creator's public key and answers with a future,
 * so that {@link PublicKeyFetch} never holds the thread that asked.
 *
 * <p>{@link HttpUrlConnectionTransport} is the one used where a caller names
 * none. It runs the JDK's blocking connection on a background thread, which
 * is the best Java 8 offers without a dependency. On Java 11 and later a
 * caller can supply a transport of its own over
 * {@code java.net.http.HttpClient.sendAsync}, which blocks no thread at all,
 * and it must keep the two rules below.</p>
 *
 * <p>The first rule is that a redirect is never followed. A creator whose
 * domain answers 3xx must read as the key being unavailable, with no request
 * made to wherever the redirect points, because otherwise a network attacker
 * able to bend the creator's DNS, or a creator that was simply
 * misconfigured, could have some other place's key trusted as the creator's
 * own and forgeries would verify.</p>
 *
 * <p>The second rule is that the URL is requested exactly as given. The
 * query names the minute the identifier was signed as the {@code date}
 * parameter, and a creator that rotates its key chooses the key by that
 * parameter, so dropping or rewriting the query fetches the wrong key and
 * every identifier signed under an earlier key reads as not matching.</p>
 */
public interface PublicKeyTransport {

    /**
     * Requests the URL and answers with the body as text.
     *
     * <p>The future completes with the body where the response code is 200,
     * and fails with a {@link PublicKeyFetchException} carrying
     * {@link OwidSignatureStatus#KEY_UNAVAILABLE} for anything else, which
     * covers any other response code, a redirect, a connection that is
     * refused, a name that does not resolve and a timeout. The method itself
     * returns at once and never throws, and it never returns null.</p>
     *
     * @param url    the URL to request, exactly as given
     * @param domain the creator domain the key is asked of, carried by the
     *               exception where the fetch fails so a caller can say whose
     *               key was wanted. The URL normally names the same host,
     *               but need not, because a test stands up an end point on
     *               the loopback address in place of the creator
     * @return the body of the response, or the failure, through a future
     */
    CompletableFuture<String> fetch(String url, String domain);
}
