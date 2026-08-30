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

/**
 * Why a read of external data succeeded or failed.
 *
 * <p>Malformed data arriving from outside is expected rather than
 * exceptional. An OWID is read from whatever a caller was handed, which on a
 * public end point means anything at all, so every one of these outcomes is
 * an ordinary result and not a fault. Reporting them by throwing costs the
 * construction and unwinding of an exception for every bad input, and
 * whoever is sending the data chooses how often that happens.</p>
 *
 * <p>These names are the cross language vocabulary. Each implementation
 * spells the surface in its own idiom, so the Java members are the Java
 * naming convention for the same set of facts, and a failure means the same
 * thing whichever language read the bytes.</p>
 */
public enum OwidParseStatus {

    /**
     * The bytes form a structurally valid OWID. This says nothing about the
     * signature, which is a separate question with its own answer.
     */
    PARSED,

    /** Nothing was supplied to read, being a null or empty value. */
    MISSING_INPUT,

    /**
     * The input was supplied in a form this surface cannot read. Kept for
     * the cross language vocabulary and not reachable in Java, where the
     * compiler already refuses anything that is not a string or a byte
     * array.
     */
    INVALID_INPUT_TYPE,

    /** The string is not valid base 64, so there are no bytes to read. */
    INVALID_BASE64,

    /** The first byte names a version this implementation does not know. */
    UNSUPPORTED_VERSION,

    /**
     * The data stopped in the middle of a field. Different from
     * {@link #BYTE_COUNT_MISMATCH}, which is a declaration disagreeing with
     * data that is all present.
     */
    UNEXPECTED_END,

    /**
     * The creator domain is not terminated, or is longer than the maximum
     * published for a domain name.
     */
    INVALID_DOMAIN_ENCODING,

    /**
     * The declared payload byte count disagrees with the bytes actually
     * present. Checked before anything is sized by the declaration, so a
     * sender cannot make a reader allocate by claiming a large payload it
     * did not send.
     */
    BYTE_COUNT_MISMATCH,

    /**
     * The envelope is structurally consistent but larger than this runtime
     * can hold. Deliberately apart from the data being wrong, because the
     * same bytes may be readable elsewhere. A Java byte array cannot hold
     * more than {@link Integer#MAX_VALUE} bytes, so a declaration larger
     * than that can never agree with the bytes present and this status is
     * not reachable from the byte array surface.
     */
    IMPLEMENTATION_CAPACITY_EXCEEDED,

    /**
     * The envelope is malformed in a way none of the others describes. A
     * fallback for the genuinely unclassified, not a substitute for naming a
     * failure that is already understood.
     */
    MALFORMED_ENVELOPE
}
