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
     * minutes.
     *
     * <p>It is used in two places. A creator that does not state the span of
     * the key it answers with reads a date later than its own now as now, so
     * within this window of now this process cannot tell whether the creator
     * read the minute as its past or as its present, and nothing learned from
     * such an answer is held or served. And a creator's signing machines may
     * not agree with the creator's own schedule to the minute, so an
     * identifier dated within this window of a key's edge that does not
     * verify under that key is checked against the neighbouring key before
     * it is reported as not matching.</p>
     */
    private static final long CLOCK_DRIFT_ALLOWANCE_MINUTES = 15;

    /** The minute {@link #minuteOf} answers where the URL names none. */
    private static final long NO_MINUTE = -1;

    /**
     * One key a creator has answered with, and the span of minutes the key
     * is known to cover.
     *
     * <p>A creator's key is in force from the start of its period until the
     * next key starts, so a key the creator confirms at two minutes was in
     * force at every minute between them. Where the creator stated the span
     * in its answer the span is explicit and complete, and an identifier
     * dated anywhere inside it is verified without a request. Otherwise the
     * span grows as the creator confirms the same key for more minutes.</p>
     */
    private static final class HeldKey {
        /** The key in PEM form, as the creator served it. */
        final String pem;
        /** The earliest minute the key is known to cover. */
        long first;
        /** The latest minute the key is known to cover. */
        long last;
        /** Whether the creator stated the whole span itself. */
        boolean explicit;

        HeldKey(String pem, long first, long last, boolean explicit) {
            this.pem = pem;
            this.first = first;
            this.last = last;
            this.explicit = explicit;
        }

        /** Whether the minute lies within the known span. */
        boolean covers(long minute) {
            return first <= minute && minute <= last;
        }
    }

    /**
     * What the cache or a fetch answers with. The key, and where it is known,
     * the span of minutes the key covers, so that a caller can tell whether
     * the identifier it is checking sits near the edge of the span.
     */
    private static final class KeyAnswer {
        final String pem;
        final long first;
        final long last;
        final boolean known;

        KeyAnswer(String pem, long first, long last, boolean known) {
            this.pem = pem;
            this.first = first;
            this.last = last;
            this.known = known;
        }

        static KeyAnswer unknown(String pem) {
            return new KeyAnswer(pem, 0, 0, false);
        }

        boolean covers(long minute) {
            return known && first <= minute && minute <= last;
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
     * week. Keyed by end point and span rather than by the whole URL, an identifier dated between two minutes the
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
    private static final Map<String, CompletableFuture<KeyAnswer>> IN_FLIGHT =
            new HashMap<String, CompletableFuture<KeyAnswer>>();

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
     *
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
     *
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
            final Owid owid, final String url, final List<Owid> others,
            final PublicKeyTransport transport) {
        return keyAtUrl(url, owid.getDomain(), transport)
                .handle((answer, failure) -> {
                    if (failure != null) {
                        return CompletableFuture.completedFuture(
                                OwidVerificationResult.of(statusOf(failure)));
                    }
                    OwidVerificationResult result = owid.verify(answer.pem,
                            others);
                    if (result.getStatus()
                            != OwidSignatureStatus.SIGNATURE_INVALID) {
                        return CompletableFuture.completedFuture(result);
                    }
                    return neighbourVerifies(owid, url, answer, others,
                            transport).thenApply(verified -> verified
                                    ? OwidVerificationResult.of(
                                            OwidSignatureStatus.SIGNATURE_VALID)
                                    : result);
                })
                .thenCompose(future -> future);
    }

    /**
     * Whether a key neighbouring the one the OWID's own minute selected
     * verifies the signature instead.
     *
     * <p>A creator's signing machines may not agree with its own schedule to
     * the minute, so an identifier dated just after a key started may have
     * been signed with the key before it, and one dated just before may have
     * been signed with the key after. Where the signature does not verify
     * under the key selected and the OWID's minute is within the clock drift
     * allowance of the edge of the span that key is known to cover, the key
     * for the minute just beyond that edge is asked for and tried. A key
     * already known to cover the neighbouring minute is not asked for again,
     * and a neighbour that turns out to be the same key is not tried again.
     * This costs at most two more requests, and only for a signature that
     * has already failed.</p>
     */
    private static CompletableFuture<Boolean> neighbourVerifies(
            final Owid owid, String url, final KeyAnswer tried,
            final List<Owid> others, PublicKeyTransport transport) {
        long minute = Io.minutesSinceBase(owid.getDate());
        if (minute < 0 || (tried.known && tried.covers(minute) == false)) {
            // Either the OWID's minute cannot be counted, or the key tried
            // was never in force at that minute, so the OWID is not near an
            // edge of that key's span.
            return CompletableFuture.completedFuture(false);
        }
        final String endPoint = endPointOf(url);
        CompletableFuture<Boolean> verified =
                CompletableFuture.completedFuture(false);
        for (final long at : new long[] {
                minute - CLOCK_DRIFT_ALLOWANCE_MINUTES,
                minute + CLOCK_DRIFT_ALLOWANCE_MINUTES}) {
            if (at < 0 || at > 0xFFFFFFFFL || tried.covers(at)) {
                continue;
            }
            verified = verified.thenCompose(already -> {
                if (already) {
                    return CompletableFuture.completedFuture(true);
                }
                return keyAtUrl(endPoint + "?date=" + at + "&format=pkcs",
                        owid.getDomain(), transport)
                        .handle((neighbour, failure) -> failure == null
                                && neighbour.pem.equals(tried.pem) == false
                                && owid.verify(neighbour.pem, others).getStatus()
                                        == OwidSignatureStatus.SIGNATURE_VALID);
            });
        }
        return verified;
    }

    /**
     * Fetches the PEM at the URL. See {@link #keyAtUrl}.
     */
    static CompletableFuture<String> publicKeyPemAtUrl(String url,
            String domain, PublicKeyTransport transport) {
        return keyAtUrl(url, domain, transport).thenApply(answer -> answer.pem);
    }

    /**
     * Fetches the key the URL asks for, with the span it is known to cover.
     * Answered from the cache where a held key is known to cover the minute
     * the URL names, from a request already under way for the same URL where
     * there is one, and otherwise through the transport. The creator's
     * answer states the moments the key is valid from and to, so the whole
     * span is held from that one answer.
     *
     * <p>The future held for a request under way is this class's own rather
     * than the transport's, so that the transport's completion can be
     * watched, the answer read and held, and a failure forgotten, all before
     * the callers waiting are answered.</p>
     */
    static CompletableFuture<KeyAnswer> keyAtUrl(final String url,
            final String domain, PublicKeyTransport transport) {
        if (transport == null) {
            return failed(new OwidException("the transport is missing"));
        }
        final String endPoint = endPointOf(url);
        final CompletableFuture<KeyAnswer> fetch;
        synchronized (LOCK) {
            KeyAnswer held = heldFor(endPoint, url);
            if (held != null) {
                return CompletableFuture.completedFuture(held);
            }
            CompletableFuture<KeyAnswer> shared = IN_FLIGHT.get(url);
            if (shared != null) {
                // Another caller asked for the same key and its fetch is
                // the one both callers share.
                return shared;
            }
            fetch = new CompletableFuture<KeyAnswer>();
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
        started.whenComplete((body, failure) -> {
            if (failure == null && body != null) {
                KeyAnswer answer;
                try {
                    answer = readAnswer(body, domain, endPoint, url);
                } catch (PublicKeyFetchException unreadable) {
                    synchronized (LOCK) {
                        forget(url, fetch);
                    }
                    fetch.completeExceptionally(unreadable);
                    return;
                }
                synchronized (LOCK) {
                    forget(url, fetch);
                }
                fetch.complete(answer);
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
     * Reads a public key answer and holds the key it carries against the
     * span it states, or against the minute asked about where it states
     * none. An answer that is not the JSON form the specification requires,
     * the PEM alone among the other forms, or that fails the checks a
     * creator applies before sending it, is reported as a key that cannot be
     * read.
     */
    private static KeyAnswer readAnswer(String body, String domain,
            String endPoint, String url) throws PublicKeyFetchException {
        PublicKeyResponse answer;
        try {
            answer = PublicKeyResponse.parse(body);
            answer.validate(null);
        } catch (OwidException e) {
            throw new PublicKeyFetchException(
                    "domain " + quoted(domain) + " answered with a public key "
                            + "answer that is not valid: " + e.getMessage(),
                    OwidSignatureStatus.INVALID_KEY, domain, 0, e);
        }
        synchronized (LOCK) {
            return hold(endPoint, url, answer.getPublicKeySpki(),
                    minutesOrNull(answer.getValidFrom()),
                    minutesOrNull(answer.getValidTo()));
        }
    }

    /** The moment as minutes since the base date, or null. */
    private static Long minutesOrNull(Instant moment) {
        if (moment == null) {
            return null;
        }
        long minutes = Io.minutesSinceBase(moment);
        return minutes < 0 ? null : Long.valueOf(minutes);
    }

    private static String quoted(String value) {
        return "'" + value + "'";
    }

    /**
     * Removes the request from those under way. Only this request is
     * removed, never whatever replaced it after the cache was emptied and a
     * fresh request started for the same URL in the meantime. Called under
     * the lock.
     */
    private static void forget(String url, CompletableFuture<KeyAnswer> fetch) {
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
     * The minute the URL asks about, or {@link #NO_MINUTE} where it names
     * none.
     */
    private static long minuteOf(String url) {
        int query = url.indexOf('?');
        if (query < 0) {
            return NO_MINUTE;
        }
        for (String pair : url.substring(query + 1).split("&")) {
            if (pair.startsWith("date=")) {
                try {
                    long minute = Long.parseLong(pair.substring(5));
                    return minute < 0 ? NO_MINUTE : minute;
                } catch (NumberFormatException notANumber) {
                    return NO_MINUTE;
                }
            }
        }
        return NO_MINUTE;
    }

    /**
     * Whether the minute lies within the clock drift allowance of now or
     * later, which is a minute a creator that does not state its spans may
     * have read as its present rather than as the minute named.
     */
    private static boolean recent(long minute) {
        return minute > Io.minutesSinceBase(Instant.now())
                - CLOCK_DRIFT_ALLOWANCE_MINUTES;
    }

    /**
     * The key held for the end point that is known to cover the minute the
     * URL asks about, or null where none is. Called under the lock.
     *
     * <p>A minute within the drift allowance of now is only served where the
     * creator itself stated the span, because a span confirmed minute by
     * minute says nothing certain about such a minute.</p>
     */
    private static KeyAnswer heldFor(String endPoint, String url) {
        long minute = minuteOf(url);
        if (minute == NO_MINUTE) {
            return null;
        }
        List<HeldKey> keys = CACHE.get(endPoint);
        if (keys != null) {
            boolean recent = recent(minute);
            for (HeldKey key : keys) {
                if (key.covers(minute) && (key.explicit || recent == false)) {
                    return new KeyAnswer(key.pem, key.first, key.last, true);
                }
            }
        }
        return null;
    }

    /**
     * Records the creator's answer to the URL, being the key and, where the
     * creator stated it, the span the key covers as the minute it came into
     * force and the minute the next key starts. Returns the key with the span
     * it is now known to cover. Called under the lock.
     *
     * <p>With both the start and the end the whole span is held as the
     * creator's own statement. With the start alone the key is held from the
     * start up to the drift allowance behind now, because no later key can
     * have started before then. With neither the minute asked about is held
     * on its own, as long as it is not within the drift allowance of now. A
     * key already held for the end point has its span widened to take in the
     * new one. A key not held before is added, emptying the cache first when
     * it is full, because the cache must not grow on the input of whoever
     * presents the identifiers.</p>
     */
    private static KeyAnswer hold(String endPoint, String url, String pem,
            Long start, Long end) {
        long minute = minuteOf(url);
        long first;
        long last;
        boolean explicit = false;
        if (start != null && end != null && end > start) {
            first = start;
            last = end - 1;
            explicit = true;
        } else if (start != null) {
            first = start;
            last = Math.max(start, Io.minutesSinceBase(Instant.now())
                    - CLOCK_DRIFT_ALLOWANCE_MINUTES);
        } else if (minute != NO_MINUTE && recent(minute) == false) {
            first = minute;
            last = minute;
        } else {
            return KeyAnswer.unknown(pem);
        }
        List<HeldKey> keys = CACHE.get(endPoint);
        if (keys != null) {
            for (HeldKey key : keys) {
                if (key.pem.equals(pem)) {
                    if (widen(keys, key, first, last)) {
                        key.explicit = key.explicit || explicit;
                        return new KeyAnswer(pem, key.first, key.last, true);
                    }
                    // The creator has answered with another key inside this
                    // span before, which it does not do unless it went back
                    // to a key it had left. Nothing more is held about it.
                    return KeyAnswer.unknown(pem);
                }
            }
            for (HeldKey other : keys) {
                if (other.last >= first && other.first <= last) {
                    return KeyAnswer.unknown(pem);
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
        keys.add(new HeldKey(pem, first, last, explicit));
        heldKeys++;
        return new KeyAnswer(pem, first, last, true);
    }

    /**
     * Widens the span of a held key to take in the span given, and says
     * whether it did.
     *
     * <p>The span is not widened across a minute the creator has answered
     * with another key for, because that would mean the creator had gone
     * back to a key it had left, and the minutes between the two spans are
     * then not this key's to claim.</p>
     */
    private static boolean widen(List<HeldKey> keys, HeldKey key, long first,
            long last) {
        first = Math.min(first, key.first);
        last = Math.max(last, key.last);
        for (HeldKey other : keys) {
            if (other != key && other.last >= first && other.first <= last) {
                return false;
            }
        }
        key.first = first;
        key.last = last;
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
