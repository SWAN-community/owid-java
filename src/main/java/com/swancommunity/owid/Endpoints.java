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

import java.time.Duration;
import java.time.Instant;
/**
 * Helpers for hosting the well known end points required by the OWID
 * specification. These are framework agnostic. They return the path and body
 * so that any HTTP server can serve them.
 *
 * <p>The mandatory end point is {@code /owid/api/v{version}/public-key},
 * returning a JSON object carrying the public key as {@code publicKey}, the
 * encoding it is in as {@code format}, and the moments it is valid from and
 * to. The one format defined is {@code spki}, which a request without the
 * parameter receives, and a request for any other value is answered
 * 400.</p>
 */
public final class Endpoints {

    private Endpoints() {
    }

    /**
     * Returns the path of the public key end point for the version provided.
     * For example {@code /owid/api/v3/public-key}.
     *
     * @param version the OWID version
     * @return the public key path
     */
    public static String publicKeyPath(Version version) {
        return "/owid/api/v" + (version.asByte() & 0xFF) + "/public-key";
    }

    /**
     * Returns the JSON body for the public key end point of a creator with
     * one key and no schedule. The key is stated as {@code publicKey} in the
     * {@code spki} format and both {@code validFrom} and {@code validTo} are
     * null, because the creator knows nothing about when the key started or
     * will stop.
     *
     * @param creator the creator
     * @param format  the format parameter, {@code spki} or null where the
     *                request has none
     * @return the JSON body
     * @throws OwidException if the format is one this library does not
     *                       serve, which a creator answers 400, or the public
     *                       key cannot be exported or read back
     */
    public static String publicKeyResponse(Creator creator, String format)
            throws OwidException {
        if (served(format) == false) {
            // The value is not repeated back, because it arrives on a query
            // string from whoever called the end point and a refusal is often
            // logged.
            throw new OwidException("the only format served is "
                    + PublicKeyResponse.SPKI_FORMAT);
        }
        return publicKeyAnswer(creator.crypto().subjectPublicKeyInfo(), null,
                null, null);
    }

    /**
     * Whether the format parameter asks for the one encoding this library
     * serves, which a request without the parameter is taken to ask for.
     */
    private static boolean served(String format) {
        return format == null || format.isEmpty()
                || PublicKeyResponse.SPKI_FORMAT.equals(format);
    }

    /**
     * Returns the JSON body of the public key end point for the key and the
     * span it covers, checked with {@link PublicKeyResponse#validate(Instant)}
     * first so that a creator never sends an answer it would itself refuse.
     *
     * @param publicKeyPem the key in PEM form
     * @param validFrom    the UTC moment the key came into force, or null
     * @param validTo      the UTC moment the next key starts, or null
     * @param asked        the moment the request asks about, or null
     * @return the JSON body
     * @throws OwidException if the answer would not be valid
     */
    public static String publicKeyAnswer(String publicKeyPem, Instant validFrom,
            Instant validTo, Instant asked) throws OwidException {
        PublicKeyResponse answer = PublicKeyResponse.of(publicKeyPem, validFrom,
                validTo);
        answer.validate(asked);
        return answer.toJson();
    }

    /**
     * The status code and body a public key end point answers a request
     * with.
     */
    public static final class Response {
        private final int status;
        private final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        /** The HTTP status code. */
        public int getStatus() {
            return status;
        }

        /** The body, empty where the status is not 200. */
        public String getBody() {
            return body;
        }
    }

    /**
     * Returns the status code and JSON body for the public key end point of
     * a creator that rotates its key, chosen from the schedule the way the
     * specification requires.
     *
     * <p>The date parameter is the OWID's own date, counted in whole minutes
     * since 2020-01-01, and the key served is the one in force then, being
     * the latest key whose start is at or before it. A request without a
     * date, or with a date later than the moment of the request, is served
     * the key in force at that moment, so a caller cannot ask for a key whose
     * period has not begun. The answer is 200 with the body from
     * {@link #publicKeyAnswer}, stating the key and the moments it is valid
     * from and to, 404 with an empty body where no key is in force at the
     * date, and 400 with an empty body where the date is not a count of
     * minutes or the format is one this creator does not serve.</p>
     *
     * @param schedule the published schedule
     * @param format   the format parameter, {@code spki} or null where the
     *                 request has none
     * @param date     the date parameter, or null where the request has none
     * @param now      the moment of the request
     * @return the status and body
     * @throws OwidException if the answer would fail its check, which is a
     *                       fault in the schedule
     */
    public static Response publicKeyResponseAt(PublicKeySchedule schedule,
            String format, String date, Instant now) throws OwidException {
        if (served(format) == false) {
            return new Response(400, "");
        }
        Instant asked = now;
        if (date != null && date.isEmpty() == false) {
            long minutes;
            try {
                minutes = Long.parseLong(date);
            } catch (NumberFormatException e) {
                return new Response(400, "");
            }
            if (minutes < 0 || minutes > 0xFFFFFFFFL) {
                return new Response(400, "");
            }
            asked = Io.baseDate().plus(Duration.ofMinutes(minutes));
            if (asked.isAfter(now)) {
                asked = now;
            }
        }
        DatedPublicKey key = schedule.keyInForce(asked);
        if (key == null) {
            return new Response(404, "");
        }
        return new Response(200, publicKeyAnswer(key.getPublicKeyPem(),
                key.getStartsAt(), schedule.nextStartAfter(key), asked));
    }
}
