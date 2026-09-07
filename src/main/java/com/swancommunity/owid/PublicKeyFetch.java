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

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

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
     * again, across every creator. A bound is needed because a verifier sees
     * identifiers from many domains and many weeks, and an unbounded store
     * would grow for as long as the process runs.
     */
    private static final int MAXIMUM_CACHED_KEYS = 1024;

    /**
     * How far a creator's clock may run ahead of or behind this one's, in
     * minutes. A minute closer to now than this, or later, is asked about
     * rather than served from the cache, and is not held.
     *
     * <p>A creator reads a date later than its own now as now, and answers
     * with the key in force now. Within this window this process cannot tell
     * whether the creator read the minute as its past or as its present, so
     * the answer says nothing certain about the minute. An identifier signed
     * just after a rotation by a creator whose clock runs ahead would
     * otherwise be served the old key from a span confirmed up to now, and
     * would read as not matching until this clock caught up. Identifiers
     * dated within the window are asked about once per minute per creator,
     * as they always were, and every older identifier is served from the
     * spans.</p>
     */
    private static final long CLOCK_DRIFT_ALLOWANCE_MINUTES = 15;

    /** The minute {@link #minuteOf} answers where the cache must not be used. */
    private static final long NOT_HELD = -1;

    /**
     * One key a creator has answered with, and the span of minutes the
     * creator has confirmed it was in force for.
     *
     * <p>A creator's key is in force from the start of its period until the
     * next key starts, so a key the creator confirms at two minutes was in
     * force at every minute between them. The span grows as the creator
     * confirms the same key for more minutes, and an identifier dated inside
     * it is verified without a request.</p>
     */
    private static final class HeldKey {
        /** The key in PEM form, as the creator served it. */
        final String pem;
        /** The earliest minute the creator has confirmed the key for. */
        long first;
        /** The latest minute the creator has confirmed the key for. */
        long last;

        HeldKey(String pem, long minute) {
            this.pem = pem;
            this.first = minute;
            this.last = minute;
        }

        /** Whether the minute lies within the confirmed span. */
        boolean covers(long minute) {
            return first <= minute && minute <= last;
        }
    }

    /**
     * Guards {@link #CACHE}, {@link #heldKeys} and {@link #IN_FLIGHT}. Held
     * across a few map and list operations only, never across a request.
     */
    private static final Object LOCK = new Object();

    /**
     * Keys already fetched, by the creator's key end point, which is the key
     * URL without its date. Each end point holds the keys the creator has
     * answered with, each with the span of minutes the creator has confirmed
     * it for.
     *
     * <p>The specification asks implementations to cache so that verifying
     * many identifiers does not mean repeating requests to another
     * processor. The key URL carries the date of the identifier being
     * verified, in minutes, and a creator's key changes on the order of a
     * week. Keyed by the whole URL, as this cache once was, two identifiers
     * signed a minute apart never shared an entry, so a hundred identifiers
     * over a hundred minutes made a hundred requests for one key. Keyed by
     * end point and span, an identifier dated between two minutes the
     * creator has already answered for is verified without a request.</p>
     */
    private static final Map<String, List<HeldKey>> CACHE =
            new HashMap<String, List<HeldKey>>();

    /** How many keys are held across every end point. */
    private static int heldKeys;

    /**
     * Requests under way, by the dated URL asked for, so that a second
     * request for a key that is still on its way joins the request already
     * made instead of making another. An entry is removed the moment its
     * request ends, whatever the outcome, so a failure is never handed to a
     * later caller and an outage is never remembered.
     */
    private static final Map<String, CompletableFuture<String>> IN_FLIGHT =
            new HashMap<String, CompletableFuture<String>>();

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
     * Empties the cache of keys already fetched, and forgets the requests
     * under way so that the next caller for any key starts a request of its
     * own. A request already under way is not stopped and still completes
     * for whoever holds its future. This is how a long running process drops
     * a key it has learned it should no longer trust, after a creator
     * rotates its key following a compromise, and how a test starts from a
     * known state.
     */
    public static void clearCache() {
        synchronized (LOCK) {
            CACHE.clear();
            heldKeys = 0;
            IN_FLIGHT.clear();
        }
    }

    /** How many keys the cache holds, for the tests. */
    static int cachedKeyCount() {
        synchronized (LOCK) {
            return heldKeys;
        }
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
     * Fetches the PEM at the URL. Answered from the cache where the creator
     * has already confirmed a key for the minute the URL names, from a
     * request already under way for the same URL where there is one, and
     * otherwise through the transport.
     *
     * <p>The future held for a request under way is this class's own rather
     * than the transport's, so that the transport's completion can be
     * watched, the key held against the minute it was asked for, and a
     * failure forgotten, all before the callers waiting are answered.</p>
     */
    static CompletableFuture<String> publicKeyPemAtUrl(final String url,
            String domain, PublicKeyTransport transport) {
        if (transport == null) {
            return failed(new OwidException("the transport is missing"));
        }
        final String endPoint = endPointOf(url);
        final long minute = minuteOf(url);
        final CompletableFuture<String> fetch;
        synchronized (LOCK) {
            String pem = minute == NOT_HELD ? null : heldPem(endPoint, minute);
            if (pem != null) {
                return CompletableFuture.completedFuture(pem);
            }
            CompletableFuture<String> held = IN_FLIGHT.get(url);
            if (held != null) {
                // Another caller asked for the same key and its fetch is
                // the one both callers share.
                return held;
            }
            fetch = new CompletableFuture<String>();
            IN_FLIGHT.put(url, fetch);
        }
        CompletableFuture<String> started;
        try {
            started = transport.fetch(url, domain);
        } catch (RuntimeException e) {
            // A transport keeps its promise by failing the future rather
            // than throwing, but one that breaks the promise must not leave
            // a future among the requests under way that never completes.
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
                // Held before the callers are answered, so a caller arriving
                // between the two finds the key rather than starting a
                // request of its own.
                synchronized (LOCK) {
                    if (minute != NOT_HELD) {
                        hold(endPoint, minute, pem);
                    }
                    forget(url, fetch);
                }
                fetch.complete(pem);
                return;
            }
            synchronized (LOCK) {
                forget(url, fetch);
            }
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

    /**
     * Removes the request from those under way. Only this request is
     * removed, never whatever replaced it after the cache was emptied and a
     * fresh request started for the same URL in the meantime. Called under
     * the lock.
     */
    private static void forget(String url, CompletableFuture<String> fetch) {
        if (IN_FLIGHT.get(url) == fetch) {
            IN_FLIGHT.remove(url);
        }
    }

    /**
     * The key URL without its query, which names the scheme, the creator and
     * the version, and so the key end point being asked.
     */
    private static String endPointOf(String url) {
        int query = url.indexOf('?');
        return query < 0 ? url : url.substring(0, query);
    }

    /**
     * The minute the cache reads the URL as asking about, or
     * {@link #NOT_HELD} where the cache must not be used for the request.
     *
     * <p>The date parameter where the URL carries one and it is at least
     * {@link #CLOCK_DRIFT_ALLOWANCE_MINUTES} behind now. A request without a
     * date asks for the key in force now, and one dated within the
     * allowance, or later, may be read by the creator as its present rather
     * than as the minute named, so neither is served from the cache nor held
     * in it.</p>
     */
    private static long minuteOf(String url) {
        long now = Io.minutesSinceBase(Instant.now());
        int query = url.indexOf('?');
        if (query < 0) {
            return NOT_HELD;
        }
        for (String pair : url.substring(query + 1).split("&")) {
            if (pair.startsWith("date=")) {
                try {
                    long minute = Long.parseLong(pair.substring(5));
                    if (minute >= 0
                            && minute <= now - CLOCK_DRIFT_ALLOWANCE_MINUTES) {
                        return minute;
                    }
                } catch (NumberFormatException notANumber) {
                    // Not a count of minutes, so nothing to hold against.
                }
                return NOT_HELD;
            }
        }
        return NOT_HELD;
    }

    /**
     * The key held for the end point whose confirmed span covers the minute,
     * or null where no held key does. Called under the lock.
     */
    private static String heldPem(String endPoint, long minute) {
        List<HeldKey> keys = CACHE.get(endPoint);
        if (keys != null) {
            for (HeldKey key : keys) {
                if (key.covers(minute)) {
                    return key.pem;
                }
            }
        }
        return null;
    }

    /**
     * Records that the creator answered the minute with the key. Called
     * under the lock.
     *
     * <p>A key already held for the end point has its span widened to take
     * in the minute. A key not held before is added, emptying the cache
     * first when it is full, because the domains and dates asked about come
     * from the identifiers presented to this process and the cache must not
     * grow on their input.</p>
     */
    private static void hold(String endPoint, long minute, String pem) {
        List<HeldKey> keys = CACHE.get(endPoint);
        if (keys != null) {
            for (HeldKey key : keys) {
                if (key.pem.equals(pem) && widen(keys, key, minute)) {
                    return;
                }
            }
        }
        if (heldKeys >= MAXIMUM_CACHED_KEYS) {
            CACHE.clear();
            heldKeys = 0;
            keys = null;
        }
        if (keys == null) {
            keys = new ArrayList<HeldKey>();
            CACHE.put(endPoint, keys);
        }
        keys.add(new HeldKey(pem, minute));
        heldKeys++;
    }

    /**
     * Widens the span of a held key to take in the minute, and says whether
     * the minute is now within it.
     *
     * <p>The span is not widened across a minute the creator has answered
     * with another key for, because that would mean the creator had gone
     * back to a key it had left, and the minutes between the two spans are
     * then not this key's to claim. The key is held again as a separate span
     * instead.</p>
     */
    private static boolean widen(List<HeldKey> keys, HeldKey key,
            long minute) {
        if (key.covers(minute)) {
            return true;
        }
        long from = Math.min(minute, key.first);
        long to = Math.max(minute, key.last);
        for (HeldKey other : keys) {
            if (other != key && other.last > from && other.first < to) {
                return false;
            }
        }
        if (minute < key.first) {
            key.first = minute;
        } else {
            key.last = minute;
        }
        return true;
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
