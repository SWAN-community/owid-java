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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Fetching the key that was in force when an identifier was signed, from the
 * well known end point on the creator domain.
 *
 * <p>The live end point answers 401 without a credential, so these tests run
 * against a stand in on the loopback address which serves the real published
 * 51d.es schedule. The URL under test is the one the library builds, with
 * only the host replaced, so a fault in the path or the query is caught
 * here.</p>
 *
 * <p>Every fetch answers with a future. The tests join the future, which is
 * fine here and is not what a caller on a request thread would do.</p>
 */
class DatedKeyFetchTest {

    /** No other OWIDs were covered by the signature on the fixture. */
    private static final List<Owid> ALONE = Collections.emptyList();

    /** The transport a caller gets without naming one. */
    private static final PublicKeyTransport HTTP =
            new HttpUrlConnectionTransport();

    /** The end points started by a test, stopped when the test ends. */
    private final List<KeyEndPoint> started = new ArrayList<KeyEndPoint>();

    @BeforeEach
    void emptyTheCache() {
        // Keys are held against the URL they were fetched from, and a test
        // that counts requests has to start from nothing held.
        PublicKeyFetch.clearCache();
    }

    @AfterEach
    void stopEndPoints() {
        for (KeyEndPoint endPoint : started) {
            endPoint.stop();
        }
        started.clear();
        PublicKeyFetch.clearCache();
    }

    /** Starts a stand in end point and stops it when the test ends. */
    private KeyEndPoint endPoint(KeyEndPoint.Answer answer)
            throws IOException, OwidException {
        KeyEndPoint endPoint = KeyEndPoint.start(answer);
        started.add(endPoint);
        return endPoint;
    }

    /** The status a fetch through the default transport ends with. */
    private static OwidSignatureStatus statusAt(Owid owid, String url) {
        return PublicKeyFetch.verifyAtUrl(owid, url, ALONE, HTTP).join()
                .getStatus();
    }

    /** The PEM a fetch through the default transport ends with. */
    private static String pemAt(String url, String domain) {
        return PublicKeyFetch.publicKeyPemAtUrl(url, domain, HTTP).join();
    }

    /**
     * The exception a failed future carries. Joining wraps it in a
     * completion exception, and the one inside is the one the library
     * raised.
     */
    private static <T extends Throwable> T failureOf(
            CompletableFuture<?> future, Class<T> type, String message) {
        CompletionException wrapped = assertThrows(CompletionException.class,
                future::join, message);
        return assertInstanceOf(type, wrapped.getCause(), message);
    }

    /**
     * The URL names the minute the identifier was created, which is the value
     * the end point selects a key by, and it names the well known path from
     * the specification.
     */
    @Test
    void urlNamesTheMinuteTheIdentifierWasCreated() throws OwidException {
        assertEquals(
                "https://51d.es/owid/api/v3/public-key?date="
                        + KeyFixtures.IDENTIFIER_MINUTES + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(KeyFixtures.identifier(),
                        "https"),
                "should ask 51d.es for the key in force on 4 September 2026");
    }

    /**
     * The version in the path comes from the version byte of the identifier
     * rather than from a constant, so an identifier written by an earlier
     * version asks the end point that serves that version.
     */
    @Test
    void urlUsesTheVersionTheIdentifierCarries() throws OwidException {
        Owid version2 = crafted(Version.VERSION2, "example.com",
                Instant.parse("2026-09-04T00:00:00Z"));
        assertEquals(Version.VERSION2, version2.getVersion(),
                "the crafted identifier is version 2");
        assertEquals(
                "https://example.com/owid/api/v2/public-key?date="
                        + KeyFixtures.IDENTIFIER_MINUTES + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(version2, "https"),
                "should ask the version 2 end point");
    }

    /** A newly signed OWID names the minute it was signed. */
    @Test
    void urlOfANewlySignedOwidNamesItsOwnMinute() throws OwidException {
        Creator creator = Creator.create("example.com", Crypto.generate());
        Owid owid = creator.createString("payload");
        assertEquals(
                "https://example.com/owid/api/v3/public-key?date="
                        + Io.minutesSinceBase(owid.getDate())
                        + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(owid, "https"),
                "should name the minute the OWID was signed");
    }

    /**
     * The fetch asks for the key in force when the identifier was signed and
     * verifies it, with the identifier signed in a week earlier than the one
     * the end point counts as current. This is the case a missing date
     * parameter broke in the Rust port, and it is the case Java had no
     * answer for at all.
     */
    @Test
    void datedFetchVerifiesAnIdentifierFromAnEarlierKeyWeek()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusAt(owid, endPoint.urlFor(owid)),
                "should verify against the key in force when it was signed");
        assertEquals(
                Collections.singletonList(
                        Long.toString(KeyFixtures.IDENTIFIER_MINUTES)),
                endPoint.dates(),
                "the request should name the minute the identifier was "
                        + "created");
    }

    /**
     * The same identifier against the same end point without the date, which
     * is the request a port that forgets the date makes. The end point
     * answers with the key in force at the moment of the request, ten days
     * after the identifier was signed, the signature does not match that
     * key, and a genuine identifier reads as a forgery.
     */
    @Test
    void undatedFetchLeavesAnEarlierWeeksIdentifierUnverified()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String undated = endPoint.base()
                + "/owid/api/v3/public-key?format=pkcs";
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                statusAt(owid, undated),
                "an undated request gets the key in force at the request, "
                        + "which did not sign it");
        assertEquals(Collections.singletonList((String) null),
                endPoint.dates(),
                "the request carried no date");
    }

    /**
     * An end point that cannot serve a key for the date leaves the signature
     * unjudged rather than reporting a genuine identifier as a forgery.
     */
    @Test
    void aKeyTheEndPointCannotServeIsKeyUnavailable()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        // A fortnight before the schedule begins, which no key in it covers,
        // so the end point answers 404 the way the cloud does.
        Instant before = KeyFixtures.scheduledKeys().get(0).startsAt()
                .minus(Duration.ofDays(14));
        String url = endPoint.base() + "/owid/api/v3/public-key?date="
                + Io.minutesSinceBase(before) + "&format=pkcs";
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                statusAt(owid, url),
                "no key means the signature was never examined");
    }

    /** The refusal carries the code and the domain, not only a message. */
    @Test
    void aRefusedRequestCarriesTheStatusAndTheCode()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String url = endPoint.base() + "/owid/api/v3/public-key?date=0"
                + "&format=pkcs";
        PublicKeyFetchException failure = failureOf(
                PublicKeyFetch.publicKeyPemAtUrl(url, "51d.es", HTTP),
                PublicKeyFetchException.class,
                "a date the schedule does not reach is refused");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                failure.getStatus(),
                "the status says the signature was never examined");
        assertEquals(404, failure.getStatusCode(),
                "the response code is carried rather than described");
        assertEquals("51d.es", failure.getDomain(),
                "the domain asked of is carried");
    }

    /**
     * An end point that cannot be reached at all leaves the signature
     * unjudged. Nothing about the identifier is known, so calling it invalid
     * would report an outage as an attack.
     */
    @Test
    void anEndPointThatCannotBeReachedIsKeyUnavailable()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = KeyEndPoint.start();
        String url = endPoint.urlFor(owid);
        endPoint.stop();
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                statusAt(owid, url),
                "a connection that is refused leaves the signature "
                        + "unjudged");
    }

    /**
     * A creator whose domain answers with a redirect does not get the key
     * at the other end trusted as its own. The other end here serves the
     * genuine schedule, so following the redirect would read as valid,
     * and refusing it must read as the key being unavailable with the
     * request to the other host never made. Without this a network
     * attacker able to bend a creator's DNS, or a misconfigured creator,
     * could substitute the key and forgeries would verify.
     */
    @Test
    void aRedirectIsNotFollowed() throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint elsewhere = endPoint(KeyEndPoint.Answer.SCHEDULE);
        KeyEndPoint creator = KeyEndPoint.start(
                KeyEndPoint.Answer.REDIRECT, elsewhere.urlFor(owid));
        started.add(creator);
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                statusAt(owid, creator.urlFor(owid)),
                "a redirect is the key being unavailable, never a key from "
                        + "wherever it points");
        assertEquals(1, creator.dates().size(),
                "the creator was asked once");
        assertTrue(elsewhere.dates().isEmpty(),
                "the request that would have gone to the other host was "
                        + "never made");
    }

    /**
     * Key material that arrives but cannot be read is the fault of the key
     * and not of the identifier, so it is reported apart from a signature
     * that does not match. 
     */
    @Test
    void aKeyThatCannotBeReadIsInvalidKey()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.BROKEN_KEY);
        assertEquals(OwidSignatureStatus.INVALID_KEY,
                statusAt(owid, endPoint.urlFor(owid)),
                "a key that cannot be read is not a signature that does not "
                        + "match");
    }

    /**
     * The key is fetched once and answered from the cache after that, which
     * is what the specification asks for so that verifying many identifiers
     * does not mean repeating requests to another processor.
     */
    @Test
    void theKeyIsFetchedOnceAndHeldAfterThat()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String url = endPoint.urlFor(owid);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusAt(owid, url),
                "the first check fetches the key");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusAt(owid, url),
                "the second check answers from the cache");
        assertEquals(1, endPoint.dates().size(),
                "the end point was asked once");
        PublicKeyFetch.clearCache();
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusAt(owid, url),
                "the check still works once the cache is emptied");
        assertEquals(2, endPoint.dates().size(),
                "emptying the cache means the key is fetched again");
    }

    /**
     * Two requests for the same key made while the first is still on its
     * way share one request. The transport here answers only when the test
     * lets it, so both requests are in flight together for certain, and
     * the count of requests the transport saw is the whole point.
     */
    @Test
    void twoRequestsInFlightForOneKeyMakeOneRequest()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String url = endPoint.urlFor(owid);
        HeldTransport held = new HeldTransport();
        CompletableFuture<String> first = PublicKeyFetch.publicKeyPemAtUrl(
                url, owid.getDomain(), held);
        CompletableFuture<String> second = PublicKeyFetch.publicKeyPemAtUrl(
                url, owid.getDomain(), held);
        assertEquals(1, held.requests.get(),
                "the second request joins the first rather than asking "
                        + "again");
        assertFalse(first.isDone(), "nothing has answered yet");
        // The genuine key, fetched through the transport itself rather than
        // through the cache, because the cache holds the fetch still on its
        // way and would hand back that same waiting future.
        held.answer.complete(HTTP.fetch(url, owid.getDomain()).join());
        assertEquals(first.join(), second.join(),
                "both callers get the one key that was fetched");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE, held).join()
                        .getStatus(),
                "the key that arrived verifies the identifier");
        assertEquals(1, held.requests.get(),
                "a key already held is not asked for again");
    }

    /**
     * A fetch that fails is not held, so the next request for the same key
     * asks again rather than repeating the failure for as long as the
     * process runs. An outage is not a fact about the key.
     */
    @Test
    void aFetchThatFailsIsNotHeld() throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String url = endPoint.urlFor(owid);
        HeldTransport held = new HeldTransport();
        CompletableFuture<String> first = PublicKeyFetch.publicKeyPemAtUrl(
                url, owid.getDomain(), held);
        held.answer.completeExceptionally(new PublicKeyFetchException(
                "the creator is away", OwidSignatureStatus.KEY_UNAVAILABLE,
                owid.getDomain(), 503, null));
        PublicKeyFetchException failure = failureOf(first,
                PublicKeyFetchException.class,
                "the failure reaches the caller as the library raised it");
        assertEquals(503, failure.getStatusCode(),
                "the failure is the one the transport gave");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusAt(owid, url),
                "the next request asks again and the key arrives");
        assertEquals(1, held.requests.get(),
                "the failed transport was asked once");
        assertEquals(1, endPoint.dates().size(),
                "the end point was asked once, by the request that came "
                        + "after the failure");
    }

    /**
     * The request runs on the executor the caller gave the transport, and
     * not on the thread that asked, which is what makes the fetch safe to
     * call from a request thread or an event loop.
     */
    @Test
    void theRequestRunsOnTheExecutorGiven()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        final AtomicReference<Thread> ran = new AtomicReference<Thread>();
        Executor executor = task -> {
            Thread thread = new Thread(task, "the executor given");
            ran.set(thread);
            thread.start();
        };
        PublicKeyTransport transport =
                new HttpUrlConnectionTransport(executor);
        String url = endPoint.urlFor(owid);
        CompletableFuture<String> fetch = transport.fetch(url,
                owid.getDomain());
        assertNotNull(ran.get(), "the executor was given the request");
        assertNotEquals(Thread.currentThread(), ran.get(),
                "the thread that asked is not the one that fetches");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                owid.verify(PublicKeyResponse.parse(fetch.join())
                        .getPublicKeySpki(), ALONE).getStatus(),
                "the key fetched on the executor verifies the identifier");
    }

    /**
     * An executor that refuses the request, because it has been shut down
     * or is full, fails the future rather than throwing at the caller, so a
     * caller has one place to look for every failure.
     */
    @Test
    void aRequestTheExecutorRefusesIsKeyUnavailable()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        Executor refusing = task -> {
            throw new RejectedExecutionException("shut down");
        };
        PublicKeyTransport transport =
                new HttpUrlConnectionTransport(refusing);
        PublicKeyFetchException failure = failureOf(
                transport.fetch(endPoint.urlFor(owid), owid.getDomain()),
                PublicKeyFetchException.class,
                "the refusal arrives through the future");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                failure.getStatus(), "no request means no key");
        assertEquals(owid.getDomain(), failure.getDomain(),
                "the domain asked of is carried");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verifyAtUrl(owid, endPoint.urlFor(owid),
                        ALONE, transport).join().getStatus(),
                "a check through the refusing executor is unjudged");
        assertTrue(endPoint.dates().isEmpty(),
                "the end point was never reached");
    }

    /** A transport has to be given where the caller names one. */
    @Test
    void aMissingTransportIsRefused()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        failureOf(PublicKeyFetch.publicKeyPem(owid, "https", null),
                OwidException.class,
                "the key cannot be fetched with no transport");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verify(owid, "https", ALONE, null).join()
                        .getStatus(),
                "a check with no transport is unjudged");
        assertThrows(IllegalArgumentException.class,
                () -> new HttpUrlConnectionTransport(null),
                "the default transport needs an executor");
    }

    /**
     * Keys are held against the URL they came from, which names the minute,
     * so two identifiers from different weeks fetch two different keys, and
     * a key held for one week never answers for another. A store keyed by
     * domain alone would hand the second identifier the first one's key.
     */
    @Test
    void keysAreHeldPerRequestAndNotPerDomain()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        Owid earlier = crafted(Version.VERSION3, KeyFixtures.IDENTIFIER_DOMAIN,
                Instant.parse("2026-08-20T00:00:00Z"));
        Owid later = crafted(Version.VERSION3, KeyFixtures.IDENTIFIER_DOMAIN,
                Instant.parse("2026-09-04T00:00:00Z"));
        String first = pemAt(endPoint.urlFor(earlier),
                KeyFixtures.IDENTIFIER_DOMAIN);
        String second = pemAt(endPoint.urlFor(later),
                KeyFixtures.IDENTIFIER_DOMAIN);
        assertNotEquals(first, second, "two weeks, two keys");
        assertEquals(2, endPoint.dates().size(), "one request per week");
        assertEquals(first, pemAt(endPoint.urlFor(earlier),
                KeyFixtures.IDENTIFIER_DOMAIN),
                "the held key is the one fetched for that week");
        assertEquals(2, endPoint.dates().size(),
                "a week already held is not asked for again");
    }

    /**
     * The domain arrives inside an OWID, which came from outside, so a value
     * that would change the shape of the URL rather than name a host in it is
     * refused before any request is made.
     */
    @Test
    void aDomainThatIsNotADomainNameIsRefused() throws OwidException {
        final Owid owid = crafted(Version.VERSION3,
                "example.com/owid/api/v3/public-key?x=",
                Instant.parse("2026-09-04T00:00:00Z"));
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(owid, "https"),
                "a domain carrying a path and a query is refused");
        failureOf(PublicKeyFetch.publicKeyPem(owid, "https"),
                OwidException.class,
                "a URL that cannot be built fails the fetch");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verify(owid, "https", ALONE).join()
                        .getStatus(),
                "a URL that cannot be built leaves the signature unjudged");
    }

    /**
     * A scheme that does not make an HTTP request is reported as a key that
     * could not be obtained, rather than escaping as a cast failure. Every
     * route into the fetch promises a status, so no route may throw
     * something unchecked past it.
     *
     * <p>The scheme used here has a handler in the JDK which opens no
     * connection at all, so the test costs nothing and reaches nobody. A
     * scheme with no handler takes the same route out, because the refusal
     * to build the URL is reported as the same status.</p>
     */
    @Test
    void aSchemeThatIsNotHttpIsKeyUnavailable() throws OwidException {
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verify(
                        KeyFixtures.identifier(), "mailto", ALONE).join()
                        .getStatus(),
                "a scheme that fetches no key leaves the signature unjudged");
    }

    /** The scheme and the OWID are both needed to build a URL. */
    @Test
    void missingValuesAreRefused() {
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(null, "https"),
                "there is no URL without an OWID");
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(
                        KeyFixtures.identifier(), "  "),
                "there is no URL without a scheme");
    }

    /**
     * A transport that answers only when the test lets it, counting the
     * requests made of it, so a test can hold two requests in flight
     * together and say how many reached the wire.
     */
    private static final class HeldTransport implements PublicKeyTransport {

        final AtomicInteger requests = new AtomicInteger();

        final CompletableFuture<String> answer =
                new CompletableFuture<String>();

        @Override
        public CompletableFuture<String> fetch(String url, String domain) {
            requests.incrementAndGet();
            return answer;
        }
    }

    /**
     * Builds an OWID with the version, domain and date given and a signature
     * of zeroes, for the cases that are about the URL rather than about the
     * signature. Reading it back is the only way an OWID reaches a caller, so
     * the bytes are written and then parsed.
     */
    private static Owid crafted(Version version, String domain, Instant date)
            throws OwidException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeByte(buffer, version.asByte());
        Io.writeString(buffer, domain);
        Io.writeDate(buffer, date, version);
        Io.writeByteArray(buffer, new byte[0]);
        Io.writeSignature(buffer, new byte[Owid.SIGNATURE_LENGTH]);
        OwidParseResult result = Owid.parse(buffer.toByteArray());
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "should read back the crafted OWID");
        Owid owid = result.getValue();
        assertNotNull(owid, "a successful read hands back the OWID");
        assertTrue(Arrays.equals(new byte[Owid.SIGNATURE_LENGTH],
                owid.getSignature()),
                "the crafted OWID carries no real signature");
        return owid;
    }

    /** The minute count for a moment, counted the way the key URL counts it. */
    private static long minutes(String moment) {
        return Io.minutesSinceBase(Instant.parse(moment));
    }

    /** A key URL on the end point for the minute given. */
    private static String urlFor(KeyEndPoint endPoint, long minute) {
        return endPoint.base() + "/owid/api/v3/public-key?date=" + minute
                + "&format=pkcs";
    }

    /** The PEM the published schedule says was in force at the minute. */
    private static String inForce(long minute) throws OwidException {
        return KeyFixtures.schedule()
                .keyInForce(Io.baseDate().plus(Duration.ofMinutes(minute)))
                .getPublicKeyPem();
    }

    /**
     * A key the creator has confirmed for two minutes is served for every
     * minute between them without a request, because a key is in force from
     * the start of its period until the next key starts. A minute outside
     * every confirmed span is asked about.
     */
    @Test
    void aMinuteBetweenTwoConfirmedMinutesIsServedFromTheCache()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SPANLESS);
        // The week of 31 August 2026, which the fixture identifier was
        // signed in, and which is wholly in the past so the cache reads
        // each minute as itself rather than as now.
        long first = minutes("2026-08-31T00:01:00Z");
        long last = minutes("2026-09-06T23:00:00Z");
        String pem = pemAt(urlFor(endPoint, first),
                KeyFixtures.IDENTIFIER_DOMAIN);
        assertEquals(pem, pemAt(urlFor(endPoint, last),
                KeyFixtures.IDENTIFIER_DOMAIN), "one key covers the week");
        assertEquals(2, endPoint.dates().size(),
                "the two ends of the span were asked about");
        for (long between : new long[] {
                first + 1, first + 3 * 24 * 60, last - 1 }) {
            assertEquals(pem, pemAt(urlFor(endPoint, between),
                    KeyFixtures.IDENTIFIER_DOMAIN),
                    "the key served for minute " + between);
        }
        assertEquals(2, endPoint.dates().size(),
                "a minute between two confirmed minutes is not asked about");
        assertEquals(1, PublicKeyFetch.cachedKeyCount(),
                "one key is held however many minutes it covers");
        assertNotEquals(pem, pemAt(urlFor(endPoint, first - 2),
                KeyFixtures.IDENTIFIER_DOMAIN),
                "a minute in the week before is the earlier week's key");
        assertEquals(3, endPoint.dates().size(),
                "a minute before the span is asked about");
        assertEquals(2, PublicKeyFetch.cachedKeyCount(),
                "the earlier week's key is held as a second key");
    }

    /**
     * The case that made the cache almost useless when it was keyed by the
     * whole URL. A hundred identifiers with a hundred different minutes
     * inside one key's period cost a hundred requests then. With the ends
     * of the period confirmed they cost none.
     */
    @Test
    void aHundredIdentifiersInOneConfirmedPeriodMakeNoRequest()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SPANLESS);
        long start = minutes("2026-09-01T00:00:00Z");
        pemAt(urlFor(endPoint, start), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, start + 100), KeyFixtures.IDENTIFIER_DOMAIN);
        for (int i = 1; i <= 100; i++) {
            pemAt(urlFor(endPoint, start + i), KeyFixtures.IDENTIFIER_DOMAIN);
        }
        assertEquals(2, endPoint.dates().size(),
                "a hundred identifiers over a hundred minutes made no "
                        + "request once both ends of the span were known");
    }

    /**
     * A key is only ever served for a minute inside the span the creator
     * has confirmed it for. Where the creator rotated between two confirmed
     * minutes, the minutes between them belong to neither key until the
     * creator is asked, and every answer agrees with the published
     * schedule.
     */
    @Test
    void aKeyIsNeverServedForAMinuteOutsideItsConfirmedSpan()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SPANLESS);
        long rotation = minutes("2026-08-31T00:00:00Z");
        long week = 7 * 24 * 60;
        // The start of the week before the rotation and the end of the week
        // after it, so the two keys are held with the rotation between.
        pemAt(urlFor(endPoint, rotation - week), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, rotation + week - 1),
                KeyFixtures.IDENTIFIER_DOMAIN);
        assertEquals(2, endPoint.dates().size());
        assertEquals(2, PublicKeyFetch.cachedKeyCount());

        // Every minute across the rotation, in an order that walks in from
        // both sides, is answered with the key the schedule gives, whether
        // from the cache or by asking.
        long[] minutes = {
                rotation - 1, rotation, rotation - 2, rotation + 1,
                rotation - week / 2, rotation + week / 2,
                rotation - 3, rotation + 2, rotation - 1, rotation };
        for (long minute : minutes) {
            assertEquals(inForce(minute), pemAt(urlFor(endPoint, minute),
                    KeyFixtures.IDENTIFIER_DOMAIN),
                    "the key served for minute " + minute);
        }
        assertEquals(2, PublicKeyFetch.cachedKeyCount(),
                "two keys are held, each with its own span");
        int asked = endPoint.dates().size();
        assertTrue(asked > 2 && asked < 2 + minutes.length,
                "some minutes were asked about and some were served: "
                        + asked);

        // The minute either side of the rotation is now confirmed, so
        // nothing across the whole fortnight needs asking.
        for (long minute = rotation - week; minute < rotation + week;
                minute += 60) {
            assertEquals(inForce(minute), pemAt(urlFor(endPoint, minute),
                    KeyFixtures.IDENTIFIER_DOMAIN),
                    "the key served for minute " + minute);
        }
        assertEquals(asked, endPoint.dates().size(),
                "both spans are fully confirmed, so nothing was asked");
    }

    /**
     * A minute within the clock drift allowance of now, or later, is asked
     * about every time and never held, because a creator whose clock differs
     * from this one's may have read it as its present rather than as the
     * minute named. A minute beyond the allowance is held as usual. Live identifiers therefore cost one request per minute per creator and older ones cost none.
     */
    @Test
    void aMinuteWithinTheDriftAllowanceIsNotHeld() throws Exception {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SPANLESS);
        Field field = PublicKeyFetch.class.getDeclaredField(
                "CLOCK_DRIFT_ALLOWANCE_MINUTES");
        field.setAccessible(true);
        long allowance = field.getLong(null);
        long started = Io.minutesSinceBase(Instant.now());
        long recent = started - 1;
        pemAt(urlFor(endPoint, recent), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, recent), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, started + 7 * 24 * 60),
                KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(endPoint.base() + "/owid/api/v3/public-key?format=pkcs",
                KeyFixtures.IDENTIFIER_DOMAIN);
        long old = started - allowance - 1;
        pemAt(urlFor(endPoint, old), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, old), KeyFixtures.IDENTIFIER_DOMAIN);
        assumeTrue(Io.minutesSinceBase(Instant.now()) == started,
                "the minute changed during the test, so the calls were not "
                        + "all about the same now");
        assertEquals(5, endPoint.dates().size(),
                "the recent minute was asked about twice, the future minute "
                        + "and the request with no date once each, and the "
                        + "old minute once with the second call held");
        assertEquals(1, PublicKeyFetch.cachedKeyCount(),
                "only the old minute's key is held");
    }

    /**
     * The cache does not grow without limit. The number of distinct keys a
     * verifier is shown is chosen by whoever presents the identifiers rather
     * than by this process, so the stand in creator here answers every
     * minute with a different key, which is the worst a creator can do to
     * the cache. The bound is read from the library so the test cannot
     * drift from it.
     */
    @Test
    void theCacheIsBounded() throws Exception {
        Field bound = PublicKeyFetch.class.getDeclaredField(
                "MAXIMUM_CACHED_KEYS");
        bound.setAccessible(true);
        int maximum = bound.getInt(null);
        final AtomicInteger requests = new AtomicInteger();
        PublicKeyTransport distinct = (url, domain) -> {
            requests.incrementAndGet();
            try {
                return CompletableFuture.completedFuture(
                        Endpoints.publicKeyAnswer(
                                Crypto.generate().subjectPublicKeyInfo(),
                                null, null, null));
            } catch (OwidException e) {
                throw new IllegalStateException(e);
            }
        };
        for (int i = 0; i <= maximum; i++) {
            PublicKeyFetch.publicKeyPemAtUrl(
                    "https://example.invalid/owid/api/v3/public-key?date=" + i
                            + "&format=pkcs",
                    "example.invalid", distinct).join();
        }
        assertEquals(maximum + 1, requests.get(),
                "every minute was a different key, so every one was asked");
        assertTrue(PublicKeyFetch.cachedKeyCount() <= maximum,
                "held " + PublicKeyFetch.cachedKeyCount() + " of at most "
                        + maximum);
    }

    /** A JSON answer for the key alone, as a creator with no schedule sends. */
    private static String spanless(String pem) throws OwidException {
        return Endpoints.publicKeyAnswer(pem, null, null, null);
    }

    /**
     * An identifier for the domain dated at the moment and signed with the
     * crypto given, standing for one whose signing machine's clock did not
     * agree with the creator's schedule to the minute.
     */
    private static Owid signedAt(String domain, Instant moment, Crypto crypto)
            throws OwidException {
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] data = Owid.dataForCrypto(Version.VERSION3, domain, moment,
                payload, ALONE);
        return new Owid(Version.VERSION3, domain, moment, payload,
                crypto.signByteArray(data));
    }

    /**
     * A creator that states the moments the key is valid from and to, which
     * is what the library's own server side helper answers, has the whole
     * span held from that one answer, so every other minute of the span is
     * served without a request.
     */
    @Test
    void aKeyAnsweredWithItsSpanIsHeldForTheWholeSpan()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String pem = pemAt(urlFor(endPoint, minutes("2026-08-31T00:01:00Z")),
                KeyFixtures.IDENTIFIER_DOMAIN);
        for (String moment : new String[] {"2026-09-06T23:59:00Z",
                "2026-09-03T12:00:00Z", "2026-08-31T00:00:00Z"}) {
            assertEquals(pem, pemAt(urlFor(endPoint, minutes(moment)),
                    KeyFixtures.IDENTIFIER_DOMAIN), moment);
        }
        assertEquals(1, endPoint.dates().size(),
                "the whole week was held from one answer");
        assertEquals(1, PublicKeyFetch.cachedKeyCount());
        assertNotEquals(pem, pemAt(urlFor(endPoint,
                minutes("2026-08-30T23:59:00Z")), KeyFixtures.IDENTIFIER_DOMAIN),
                "the minute before the week is the earlier week's key");
        pemAt(urlFor(endPoint, minutes("2026-08-24T00:00:00Z")),
                KeyFixtures.IDENTIFIER_DOMAIN);
        assertEquals(2, endPoint.dates().size(),
                "the earlier week was held from its one answer");
    }

    /**
     * The drift allowance, which keeps minutes near now out of a cache built
     * from confirmed minutes, does not apply to a span the creator stated
     * itself, so live identifiers cost one request per key rather than one
     * per minute.
     */
    @Test
    void aRecentMinuteIsServedWhereTheCreatorStatedTheSpan()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        Instant now = Instant.now();
        DatedPublicKey current = KeyFixtures.schedule().keyInForce(now);
        assumeTrue(current != null
                && KeyFixtures.schedule().nextStartAfter(current) != null,
                "the fixture schedule has no key after the one in force now");
        long started = Io.minutesSinceBase(now);
        pemAt(urlFor(endPoint, started - 1), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, started), KeyFixtures.IDENTIFIER_DOMAIN);
        pemAt(urlFor(endPoint, started - 10), KeyFixtures.IDENTIFIER_DOMAIN);
        assertEquals(1, endPoint.dates().size(),
                "the current key was served for every recent minute from one "
                        + "answer");
    }

    /**
     * An identifier dated just after a key started, but signed with the key
     * before it, verifies, and one dated just before a key started but
     * signed with it verifies too, because the neighbouring key is tried
     * when the selected key fails within the drift allowance of the span's
     * edge. Further from the edge the failure stands. The stand in creator
     * answers with the library's own server side helper, so the loop between
     * the two halves of the library is closed.
     */
    @Test
    void aSignatureFailingNearTheEdgeOfASpanIsCheckedAgainstTheNeighbour()
            throws OwidException {
        Crypto first = Crypto.generate();
        Crypto second = Crypto.generate();
        Crypto third = Crypto.generate();
        Instant rotation = Instant.parse("2026-08-31T00:00:00Z");
        Duration week = Duration.ofDays(7);
        final PublicKeySchedule schedule = PublicKeySchedule.of(Arrays.asList(
                DatedPublicKey.of(rotation.minus(week),
                        first.subjectPublicKeyInfo()),
                DatedPublicKey.of(rotation, second.subjectPublicKeyInfo()),
                DatedPublicKey.of(rotation.plus(week),
                        third.subjectPublicKeyInfo())));
        final List<String> requests = new ArrayList<String>();
        PublicKeyTransport creator = (url, domain) -> {
            requests.add(url);
            String date = null;
            int at = url.indexOf("date=");
            if (at >= 0) {
                date = url.substring(at + 5, url.indexOf('&', at));
            }
            try {
                Endpoints.Response response = Endpoints.publicKeyResponseAt(
                        schedule, "pkcs", date, Instant.now());
                return CompletableFuture.completedFuture(response.getBody());
            } catch (OwidException e) {
                throw new IllegalStateException(e);
            }
        };
        Owid late = signedAt("creator.test", rotation.plus(Duration.ofMinutes(5)),
                first);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusOf(late, creator),
                "signed with the earlier key just after the rotation");
        assertEquals(2, requests.size(),
                "the selected key and then the earlier key were asked for");
        Owid early = signedAt("creator.test",
                rotation.minus(Duration.ofMinutes(5)), second);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusOf(early, creator),
                "signed with the later key just before the rotation");
        assertEquals(2, requests.size(), "both keys are held with their spans");
        Owid far = signedAt("creator.test", rotation.plus(Duration.ofMinutes(20)),
                first);
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                statusOf(far, creator), "well inside the later key's span");
        assertEquals(2, requests.size(),
                "the neighbouring minutes lie inside the spans held");
        Owid genuine = signedAt("creator.test", rotation.plus(Duration.ofDays(3)),
                second);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                statusOf(genuine, creator));
        Owid forged = signedAt("creator.test", rotation.plus(Duration.ofDays(3)),
                third);
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                statusOf(forged, creator),
                "signed with a key not in force at its date");
    }

    /** The status of an OWID checked through the transport given. */
    private static OwidSignatureStatus statusOf(Owid owid,
            PublicKeyTransport transport) throws OwidException {
        return PublicKeyFetch.verifyAtUrl(owid,
                PublicKeyFetch.publicKeyUrl(owid, "https"), ALONE, transport)
                .join().getStatus();
    }

    /**
     * The PEM alone as text is reported as a key this library cannot read
     * rather than used, and so is a span that ends before it starts.
     */
    @Test
    void anAnswerThatIsNotTheJsonFormIsAKeyThatCannotBeRead()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.PEM_ONLY);
        assertEquals(OwidSignatureStatus.INVALID_KEY,
                statusAt(owid, endPoint.urlFor(owid)));
        final String pem = KeyFixtures.schedule().getKeys().get(0).getPublicKeyPem();
        PublicKeyTransport contradictory = (url, domain) ->
                CompletableFuture.completedFuture(PublicKeyResponse.of(pem,
                        Instant.parse("2026-08-31T00:00:00Z"),
                        Instant.parse("2026-08-24T00:00:00Z")).toJson());
        assertEquals(OwidSignatureStatus.INVALID_KEY,
                statusOf(owid, contradictory));
    }

    /**
     * Threads verifying the same OWID at the same moment make one request for
     * its key between them, and every one of them gets the answer. The stand
     * in transport holds its answer until every thread has asked, so all of
     * them are in flight together against one request.
     */
    @Test
    void manyThreadsVerifyingOneOwidTogetherMakeOneRequest()
            throws Exception {
        final int callers = 32;
        final Owid owid = KeyFixtures.identifier();
        final String answer = spanless(
                KeyFixtures.schedule().keyFor(owid).getPublicKeyPem());
        final AtomicInteger requests = new AtomicInteger();
        final CompletableFuture<String> held = new CompletableFuture<String>();
        PublicKeyTransport transport = (url, domain) -> {
            requests.incrementAndGet();
            return held;
        };
        final String url = PublicKeyFetch.publicKeyUrl(owid, "https");
        final CyclicBarrier start = new CyclicBarrier(callers + 1);
        final List<OwidSignatureStatus> statuses = Collections.synchronizedList(
                new ArrayList<OwidSignatureStatus>());
        List<Thread> threads = new ArrayList<Thread>();
        for (int i = 0; i < callers; i++) {
            Thread thread = new Thread(() -> {
                try {
                    start.await();
                    statuses.add(PublicKeyFetch.verifyAtUrl(owid, url, ALONE,
                            transport).join().getStatus());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            thread.start();
            threads.add(thread);
        }
        // Every thread goes at the same moment, and the transport only
        // answers once they are all waiting on it.
        start.await();
        Thread.sleep(200);
        held.complete(answer);
        for (Thread thread : threads) {
            thread.join(30_000);
        }
        assertEquals(callers, statuses.size(), "every thread finished");
        for (OwidSignatureStatus status : statuses) {
            assertEquals(OwidSignatureStatus.SIGNATURE_VALID, status,
                    "every thread verified the OWID");
        }
        assertEquals(1, requests.get(), "one request for " + callers + " threads");
    }
}
