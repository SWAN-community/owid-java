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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/** Unit tests for the well known end point helpers. */
class EndpointsTest {

    private static Creator newCreator() throws OwidException {
        return Creator.create("example.com", Crypto.generate());
    }

    @Test
    void paths() {
        assertEquals("/owid/api/v3/public-key",
                Endpoints.publicKeyPath(Version.VERSION3),
                "should match the public key path");
    }

    /**
     * The format parameter names the encoding of the key in the answer. The
     * one encoding defined is answered whether or not it is asked for by
     * name, the answer echoes it, and any other value is refused rather than
     * answered in an encoding the caller did not ask for.
     */
    @Test
    void publicKeyResponseFormats() throws OwidException {
        Creator creator = newCreator();
        for (String format : new String[] {"spki", null, ""}) {
            String body = Endpoints.publicKeyResponse(creator, format);
            PublicKeyResponse answer = PublicKeyResponse.parse(body);
            assertEquals("spki", answer.getFormat(),
                    "the answer names the encoding of the key");
            assertTrue(answer.getPublicKey().contains("BEGIN PUBLIC KEY"),
                    "should return the PEM for format " + format);
            assertNull(answer.getValidFrom(), "a single key has no schedule");
            assertNull(answer.getValidTo());
        }
        for (String format : new String[] {"pkcs", "other"}) {
            assertThrows(OwidException.class,
                    () -> Endpoints.publicKeyResponse(creator, format),
                    "should refuse format " + format);
        }
    }

    /**
     * The scheduled form answers 400 to a format it does not serve, the way
     * the specification requires of a creator, and answers the one format
     * defined whether or not the request names it.
     */
    @Test
    void publicKeyResponseAtRefusesAnotherFormat() throws OwidException {
        Instant now = Instant.parse("2026-09-07T12:00:00Z");
        PublicKeySchedule schedule = PublicKeySchedule.of(
                Collections.singletonList(DatedPublicKey.of(
                        Instant.parse("2026-08-31T00:00:00Z"),
                        Crypto.generate().subjectPublicKeyInfo())));
        Endpoints.Response refused = Endpoints.publicKeyResponseAt(schedule,
                "pkcs", null, now);
        assertEquals(400, refused.getStatus(),
                "a format this creator does not serve is a bad request");
        assertEquals("", refused.getBody());
        for (String format : new String[] {"spki", null}) {
            Endpoints.Response served = Endpoints.publicKeyResponseAt(
                    schedule, format, null, now);
            assertEquals(200, served.getStatus());
            assertEquals("spki",
                    PublicKeyResponse.parse(served.getBody()).getFormat(),
                    "the answer echoes the one format defined");
        }
    }
}
