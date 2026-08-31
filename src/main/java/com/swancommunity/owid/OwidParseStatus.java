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
     *
     * <p>Reading one frame out of something longer, this also covers a frame
     * whose declared payload and signature run past the bytes supplied, so a
     * caller reading from a source that is still arriving can wait for more
     * and read again from the same place.</p>
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
     *
     * <p>Only the whole buffer read reports this, because only there does the
     * envelope have to end where the input does. Reading one frame out of
     * something longer, bytes after the signature are the next frame rather
     * than a disagreement, and a frame that runs past the input is
     * {@link #UNEXPECTED_END}.</p>
     */
    BYTE_COUNT_MISMATCH,

    /**
     * The envelope is structurally consistent but larger than this runtime
     * can hold. Deliberately apart from the data being wrong, because the
     * same bytes may be readable elsewhere.
     *
     * <p>Not reachable in Java, and so not covered by a test. A Java byte
     * array cannot hold more than {@link Integer#MAX_VALUE} bytes, so a
     * declaration larger than that can neither equal the bytes present, which
     * is what the whole buffer read requires, nor be covered by them, which
     * is what the framed read requires. The guard is kept so a future change
     * to that arithmetic cannot silently truncate the declaration.</p>
     */
    IMPLEMENTATION_CAPACITY_EXCEEDED,

    /**
     * The envelope is malformed in a way none of the others describes. A
     * fallback for the genuinely unclassified, not a substitute for naming a
     * failure that is already understood.
     *
     * <p>Not reachable in Java today, on either reading surface, and so not
     * covered by a test. Every failure these readers can meet is classified
     * by one of the members above. The one place that still reports this is
     * the check that the envelope ended where the input did, which the framed
     * read does not apply at all and which cannot fire on the whole buffer
     * read while the declared payload count has already been required to
     * leave exactly the signature. That check is kept as a backstop rather
     * than removed, because a future change to the count arithmetic would
     * otherwise start accepting bytes after the signature in silence.
     * Loosening the count rule during a deliberate check of the tests made
     * this status appear, so the backstop does work.</p>
     */
    MALFORMED_ENVELOPE
}
