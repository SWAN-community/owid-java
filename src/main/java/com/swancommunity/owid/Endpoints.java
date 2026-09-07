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
 * <p>The mandatory end points are:</p>
 *
 * <ul>
 *   <li>{@code /owid/api/v{version}/creator} returning JSON with the domain,
 *       common name, and public key of the creator.</li>
 *   <li>{@code /owid/api/v{version}/public-key} returning the public key as
 *       PEM text. The {@code format} query parameter must be {@code spki} or
 *       {@code pkcs}.</li>
 * </ul>
 */
public final class Endpoints {

    private Endpoints() {
    }

    /**
     * Returns the path of the creator end point for the version provided. For
     * example {@code /owid/api/v3/creator}.
     *
     * @param version the OWID version
     * @return the creator path
     */
    public static String creatorPath(Version version) {
        return "/owid/api/v" + (version.asByte() & 0xFF) + "/creator";
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
     * Returns the JSON body for the creator end point. The JSON has the
     * fields domain, name, publicKeySPKI, and contractURL named exactly as
     * required by the specification.
     *
     * @param creator     the creator
     * @param name        the common name of the creator
     * @param contractUrl the URL with the terms associated with the data
     * @return the JSON body
     * @throws OwidException if the public key cannot be exported
     */
    public static String creatorResponse(Creator creator, String name,
            String contractUrl) throws OwidException {
        String spki = creator.crypto().subjectPublicKeyInfo();
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendField(json, "domain", creator.domain());
        json.append(',');
        appendField(json, "name", name);
        json.append(',');
        appendField(json, "publicKeySPKI", spki);
        json.append(',');
        appendField(json, "contractURL", contractUrl);
        json.append('}');
        return json.toString();
    }

    /**
     * Returns the JSON body for the public key end point of a creator with
     * one key and no schedule. The key is stated as {@code publicKeySPKI} and
     * both {@code validFrom} and {@code validTo} are null, because the
     * creator knows nothing about when the key started or will stop.
     *
     * <p>The specification allows the key to be requested in SPKI or PKCS
     * form. This implementation returns the SPKI PEM for both values because
     * the importers accept it.</p>
     *
     * @param creator the creator
     * @param format  the format parameter, {@code spki} or {@code pkcs}
     * @return the JSON body
     * @throws OwidException if the format is not valid, or the public key
     *                       cannot be exported or read back
     */
    public static String publicKeyResponse(Creator creator, String format)
            throws OwidException {
        if ("spki".equals(format) == false && "pkcs".equals(format) == false) {
            // The value is not repeated back, because it arrives on a query
            // string from whoever called the end point and a refusal is often
            // logged.
            throw new OwidException(
                    "format parameter 'spki' or 'pkcs' must be provided");
        }
        return publicKeyAnswer(creator.crypto().subjectPublicKeyInfo(), null,
                null, null);
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
     * minutes.</p>
     *
     * @param schedule the published schedule
     * @param format   the format parameter, {@code spki} or {@code pkcs}
     * @param date     the date parameter, or null where the request has none
     * @param now      the moment of the request
     * @return the status and body
     * @throws OwidException if the format is not valid, or the answer would
     *                       fail its check, which is a fault in the schedule
     */
    public static Response publicKeyResponseAt(PublicKeySchedule schedule,
            String format, String date, Instant now) throws OwidException {
        if ("spki".equals(format) == false && "pkcs".equals(format) == false) {
            throw new OwidException(
                    "format parameter 'spki' or 'pkcs' must be provided");
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

    private static void appendField(StringBuilder json, String name,
            String value) {
        json.append('"').append(name).append("\":\"")
                .append(escape(value)).append('"');
    }

    /** Escapes a string for inclusion in a JSON string literal. */
    private static String escape(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    } else {
                        builder.append(c);
                    }
            }
        }
        return builder.toString();
    }
}
