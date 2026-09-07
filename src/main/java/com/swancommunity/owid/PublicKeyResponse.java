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
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The JSON body of the public key end point. It carries the key together with
 * the moments it is valid from and to, in UTC, so a client holds the key for
 * the whole span from one answer rather than asking again for every minute.
 *
 * <p>{@code validFrom} is null where the creator has a single key and no
 * schedule, and {@code validTo} is null where no later key has been
 * scheduled. Both the creator that sends the answer and the client that reads
 * it check it with {@link #validate(Instant)}, so a fault in a creator's
 * schedule or store is a server error at the creator rather than a bad answer
 * a client then has to refuse.</p>
 *
 * <p>Only the JDK is used, so the library keeps its promise of no runtime
 * dependencies. The answer is a flat object of three fields, each a string or
 * null, which is all the reading and writing here supports.</p>
 */
public final class PublicKeyResponse {

    private final String publicKeySpki;
    private final Instant validFrom;
    private final Instant validTo;

    private PublicKeyResponse(String publicKeySpki, Instant validFrom,
            Instant validTo) {
        this.publicKeySpki = publicKeySpki;
        this.validFrom = validFrom;
        this.validTo = validTo;
    }

    /**
     * An answer for the key and the moments it is valid from and to, either
     * of which may be null.
     *
     * @param publicKeySpki the key in PEM form
     * @param validFrom     the UTC moment the key came into force, or null
     * @param validTo       the UTC moment the next key starts, or null
     * @return the answer, not yet checked
     */
    public static PublicKeyResponse of(String publicKeySpki, Instant validFrom,
            Instant validTo) {
        return new PublicKeyResponse(publicKeySpki, validFrom, validTo);
    }

    /** The key in PEM form. */
    public String getPublicKeySpki() {
        return publicKeySpki;
    }

    /** The UTC moment the key came into force, or null where not known. */
    public Instant getValidFrom() {
        return validFrom;
    }

    /** The UTC moment the next key starts, or null where none is scheduled. */
    public Instant getValidTo() {
        return validTo;
    }

    /**
     * Checks the answer the way both the creator that sends it and the client
     * that reads it must. The key must be a public key this library can read,
     * a key valid to a moment must be valid from an earlier one, and where the
     * moment asked about is known the key must have come into force by then
     * and, if it has an end, not have ended.
     *
     * @param asked the moment asked about, or null where it is not known
     * @throws OwidException if the answer is not valid
     */
    public void validate(Instant asked) throws OwidException {
        if (publicKeySpki == null || publicKeySpki.trim().isEmpty()) {
            throw new OwidException("the public key answer holds no key");
        }
        try {
            Crypto.newVerifyOnly(publicKeySpki);
        } catch (OwidException e) {
            throw new OwidException(
                    "the public key answer holds a key that cannot be read");
        }
        if (validTo != null) {
            if (validFrom == null) {
                throw new OwidException("the public key answer states when "
                        + "the key ends but not when it started");
            }
            if (validTo.isAfter(validFrom) == false) {
                throw new OwidException("the public key answer states a key "
                        + "that ends before it starts");
            }
        }
        if (asked != null) {
            if (validFrom != null && validFrom.isAfter(asked)) {
                throw new OwidException("the public key answer states a key "
                        + "that had not started at the moment asked about");
            }
            if (validTo != null && validTo.isAfter(asked) == false) {
                throw new OwidException("the public key answer states a key "
                        + "that had ended at the moment asked about");
            }
        }
    }

    /**
     * The answer as JSON, with the moments as RFC 3339 strings in UTC and
     * null where there is no moment.
     *
     * @return the JSON body
     */
    public String toJson() {
        StringBuilder json = new StringBuilder("{\"publicKeySPKI\":");
        appendString(json, publicKeySpki);
        json.append(",\"validFrom\":");
        appendMoment(json, validFrom);
        json.append(",\"validTo\":");
        appendMoment(json, validTo);
        return json.append('}').toString();
    }

    /**
     * Reads an answer from its JSON body.
     *
     * @param json the body
     * @return the answer, not yet checked with {@link #validate(Instant)}
     * @throws OwidException if the body is not a JSON object of the three
     *                       fields, each a string or null
     */
    public static PublicKeyResponse parse(String json) throws OwidException {
        Map<String, String> fields = readFlatObject(json);
        return new PublicKeyResponse(
                fields.get("publicKeySPKI"),
                moment(fields.get("validFrom"), "validFrom"),
                moment(fields.get("validTo"), "validTo"));
    }

    private static Instant moment(String text, String field)
            throws OwidException {
        if (text == null) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new OwidException("the public key answer's " + field
                    + " is not a moment in UTC");
        }
    }

    private static void appendMoment(StringBuilder json, Instant moment) {
        if (moment == null) {
            json.append("null");
        } else {
            appendString(json, moment.toString());
        }
    }

    private static void appendString(StringBuilder json, String value) {
        if (value == null) {
            json.append("null");
            return;
        }
        json.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    json.append("\\\"");
                    break;
                case '\\':
                    json.append("\\\\");
                    break;
                case '\n':
                    json.append("\\n");
                    break;
                case '\r':
                    json.append("\\r");
                    break;
                case '\t':
                    json.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        json.append(String.format("\\u%04x", (int) c));
                    } else {
                        json.append(c);
                    }
            }
        }
        json.append('"');
    }

    /**
     * Reads a JSON object whose values are strings or null. Anything else is
     * refused, because the answer has no other shape.
     */
    private static Map<String, String> readFlatObject(String json)
            throws OwidException {
        Map<String, String> fields = new LinkedHashMap<String, String>();
        if (json == null) {
            throw notJson();
        }
        int[] at = {skipSpace(json, 0)};
        if (at[0] >= json.length() || json.charAt(at[0]) != '{') {
            throw notJson();
        }
        at[0]++;
        at[0] = skipSpace(json, at[0]);
        if (at[0] < json.length() && json.charAt(at[0]) == '}') {
            return fields;
        }
        while (true) {
            at[0] = skipSpace(json, at[0]);
            String name = readString(json, at);
            at[0] = skipSpace(json, at[0]);
            if (at[0] >= json.length() || json.charAt(at[0]) != ':') {
                throw notJson();
            }
            at[0]++;
            at[0] = skipSpace(json, at[0]);
            if (json.startsWith("null", at[0])) {
                fields.put(name, null);
                at[0] += 4;
            } else {
                fields.put(name, readString(json, at));
            }
            at[0] = skipSpace(json, at[0]);
            if (at[0] >= json.length()) {
                throw notJson();
            }
            char next = json.charAt(at[0]);
            at[0]++;
            if (next == '}') {
                break;
            }
            if (next != ',') {
                throw notJson();
            }
        }
        if (skipSpace(json, at[0]) != json.length()) {
            throw notJson();
        }
        return fields;
    }

    private static int skipSpace(String json, int at) {
        while (at < json.length() && Character.isWhitespace(json.charAt(at))) {
            at++;
        }
        return at;
    }

    private static String readString(String json, int[] at)
            throws OwidException {
        if (at[0] >= json.length() || json.charAt(at[0]) != '"') {
            throw notJson();
        }
        at[0]++;
        StringBuilder value = new StringBuilder();
        while (at[0] < json.length()) {
            char c = json.charAt(at[0]++);
            if (c == '"') {
                return value.toString();
            }
            if (c != '\\') {
                value.append(c);
                continue;
            }
            if (at[0] >= json.length()) {
                throw notJson();
            }
            char escaped = json.charAt(at[0]++);
            switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    value.append(escaped);
                    break;
                case 'b':
                    value.append('\b');
                    break;
                case 'f':
                    value.append('\f');
                    break;
                case 'n':
                    value.append('\n');
                    break;
                case 'r':
                    value.append('\r');
                    break;
                case 't':
                    value.append('\t');
                    break;
                case 'u':
                    if (at[0] + 4 > json.length()) {
                        throw notJson();
                    }
                    try {
                        value.append((char) Integer.parseInt(
                                json.substring(at[0], at[0] + 4), 16));
                    } catch (NumberFormatException e) {
                        throw notJson();
                    }
                    at[0] += 4;
                    break;
                default:
                    throw notJson();
            }
        }
        throw notJson();
    }

    private static OwidException notJson() {
        return new OwidException("the public key answer is not the JSON "
                + "object of three fields the specification requires");
    }
}
