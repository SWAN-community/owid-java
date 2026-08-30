![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) for Java

Simple cryptographically auditable identifiers and processors implemented in
pure Java with no external runtime dependencies.

## Overview

An OWID records that the entity operating a domain captured or generated a
payload at a date and time, with an ECDSA signature over the OWID and any
other OWIDs it was signed together with. OWIDs chain together to form
verifiable trees. The cryptography is ECDSA on the NIST P-256 curve (also
known as secp256r1 or prime256v1) with the SHA-256 hash.

Read the [OWID project](https://github.com/SWAN-community/owid) to learn more
about the concepts before looking into this implementation. This library
creates, signs, serializes, and verifies OWIDs.

## Scope of this implementation

- Pure JDK. The only build and test dependency is JUnit 5. There are no
  runtime dependencies, so the library is a single small JAR.
- Reading supports versions 1, 2, and 3. Writing and signing always use the
  current version, version 3.
- Private keys are imported from PKCS#8 ("PRIVATE KEY") PEM. The SEC1
  ("EC PRIVATE KEY") PEM form is not supported because the JDK cannot parse
  it without an additional ASN.1 provider. Keys exported by this library, and
  the keys used across the test fixtures, use PKCS#8 and SPKI, so this
  limitation does not affect interoperability.
- Public keys are imported from Subject Public Key Info ("PUBLIC KEY") PEM.
- The well known end point helpers return paths and bodies. They do not bind
  to any web framework.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain has no
separate encoded maximum, so the protocol alone is not an application input
limit for the complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it sizes or copies the payload. A large declaration without
the corresponding bytes is malformed, and is reported as
`BYTE_COUNT_MISMATCH` without allocating the declared size. A matching large
payload is not malformed merely because it is large, and parsing work and
memory use scale with the bytes actually present.

The in-memory APIs remain subject to Java's signed `int` array indexing,
address-space and available-memory limits, so a single Java byte array cannot
represent every value allowed by the unsigned wire field. Applications
accepting untrusted OWIDs must choose limits suitable for their use case and
enforce them before buffering the binary form or decoding Base64. An
implementation capacity failure or an application policy rejection is
distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope; allow
for the domain and other OWID fields as well as the payload. After parsing,
`owid.getPayloadLength()` reports the actual payload size without copying it
and can be used for downstream policy. The parser cannot choose either limit
on behalf of the application.

## Installation

Build and install with Maven. The library is compiled for Java 8, and the
test suite runs on Java 8, 11, 17 and 21.

```
mvn install
```

Then depend on it from another Maven project.

```xml
<dependency>
    <groupId>io.github.swan-community</groupId>
    <artifactId>owid</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

The example below is compiled and run by the test suite as
`ReadmeExampleTest`, so a change to the library that would break it fails the
build rather than leaving a documented example that no longer works.

```java
import com.swancommunity.owid.Creator;
import com.swancommunity.owid.Crypto;
import com.swancommunity.owid.Owid;
import com.swancommunity.owid.OwidParseResult;

import java.util.Collections;

// The creator operates a domain and holds the signing keys.
Crypto crypto = Crypto.generate();
Creator creator = Creator.create("example.com", crypto);

// Create a signed OWID with a payload. An OWID is signed from the moment it
// exists, so there is never an unsigned one to hold.
Owid owid = creator.createString("Hello World");

// Serialize to base 64 for storage or transmission.
String encoded = owid.asBase64();

// Later, or elsewhere, read it back. Reading answers rather than throwing,
// because whatever arrives from outside may not be an OWID at all.
OwidParseResult result = Owid.tryParse(encoded);
if (result.isSuccess()) {
    Owid copy = result.getValue();
    String publicPem = crypto.publicKeyPem();
    boolean valid = copy.verifyWithPublicKey(
        publicPem, Collections.<Owid>emptyList());
} else {
    // result.getStatus() names which of the expected problems it was, and
    // result.getValue() is null.
}
```

Chaining covers other OWIDs with the same signature. The same others, in the
same order, must be supplied when verifying as were supplied when signing.

```java
Owid root = creator.createString("root");
Owid party = creator.createString("party", Collections.singletonList(root));

// Verifies with the root as the single other, fails without it.
party.verifyWithCrypto(crypto, Collections.singletonList(root)); // true
party.verifyWithCrypto(crypto, Collections.<Owid>emptyList());   // false
```

## Reading, and why it does not throw

An OWID is read from whatever a caller was handed, which on a public end
point means anything at all, so malformed data is an ordinary outcome rather
than an exceptional one. `Owid.tryParse` and `Owid.tryParseBytes` therefore
report three facts every time.

| Fact | Where |
|------|-------|
| Whether it worked | `isSuccess()` |
| The OWID, only when it worked | `getValue()`, null otherwise |
| A named reason, either way | `getStatus()` |

The statuses are the cross language vocabulary, so a failure means the same
thing whichever language read the bytes.

| Status | Meaning |
|--------|---------|
| `PARSED` | The bytes are a structurally valid OWID. |
| `MISSING_INPUT` | Nothing was supplied to read. |
| `INVALID_INPUT_TYPE` | Not reachable in Java, where the compiler already refuses anything that is not a string or a byte array. |
| `INVALID_BASE64` | The string is not base 64, so there are no bytes to read. |
| `UNSUPPORTED_VERSION` | The first byte names a version this library does not know. |
| `UNEXPECTED_END` | The data stopped in the middle of a field. |
| `INVALID_DOMAIN_ENCODING` | The domain is unterminated, or longer than the published maximum. |
| `BYTE_COUNT_MISMATCH` | The declared payload count disagrees with the bytes present. |
| `IMPLEMENTATION_CAPACITY_EXCEEDED` | Larger than this runtime can hold. Not reachable from the byte array surface, because a Java array cannot exceed `Integer.MAX_VALUE` bytes and so can never agree with a larger declaration. |
| `MALFORMED_ENVELOPE` | Malformed in a way none of the others describes. |

Reading and verifying are separate questions, and reading fetches no key and
performs no cryptography. Bytes that are a well formed OWID read successfully
even when the signature does not match, and only `verifyDetailed` then
reports that it does not.

`verifyDetailed` keeps "does not match" apart from "could not check", because
a key that cannot be obtained or cannot be decoded leaves the signature
unjudged, and reporting that as invalid would read as an attack rather than
as the outage it is.

| Status | Meaning |
|--------|---------|
| `SIGNATURE_VALID` | Genuine for this data and this key. |
| `SIGNATURE_INVALID` | Well formed and does not match. The only status that means the identifier should be distrusted. |
| `INVALID_SIGNATURE_LENGTH` | A signature field of the wrong length reached the check. |
| `KEY_UNAVAILABLE` | No key was supplied, or the one supplied cannot verify. |
| `INVALID_KEY` | Key material arrived and cannot be decoded or used. |
| `IMPLEMENTATION_CAPACITY_EXCEEDED` | More work than this runtime can hold. |
| `VERIFICATION_ERROR` | The check could not be completed for a reason that is not the identifier's fault. |

## How an OWID comes into being

An OWID is only worth anything because it is signed, so a caller cannot build
one. There is no public constructor and no setter, and an instance reaches
calling code by exactly two routes.

1. A successful read of a complete serialized OWID, through `Owid.tryParse`
   or `Owid.tryParseBytes`.
2. A creator signing one into existence, through `createString` or
   `createBytes`.

An unsigned OWID is indistinguishable from a signed one to the code
downstream of it, and the difference only surfaces later when a verification
fails somewhere nobody is watching, which is why there is no way to obtain
one. There is no public way to sign an OWID either, because with nothing
unsigned to hold there is nothing outside to sign, and signing a parsed OWID
again would replace the signature its fields were read with.

The fields are read only for the same reason. The signature covers them as
they arrived, so a caller changing one afterwards would hold something the
signature no longer describes. `getPayload` and `getSignature` hand back
copies, because a Java byte array is mutable.

## Migrating from the earlier surface

| Before | After |
|--------|-------|
| `Owid.fromBase64(value)` | `Owid.tryParse(value)` |
| `Owid.fromByteArray(buffer)` | `Owid.tryParseBytes(buffer)` |
| `new Owid()`, then `setPayload`, then `creator.sign(owid)` | `creator.createBytes(payload)` |
| `creator.signString(value)` | `creator.createString(value)` |
| `creator.signBytes(value)` | `creator.createBytes(value)` |
| `new Owid()`, then `creator.signWithOthers(owid, others)` | `creator.createBytes(payload, others)` |
| `owid.setVersion`, `setDomain`, `setDate`, `setPayload` | no replacement, the state is read only |
| `Version.fromByte(b)` | no replacement, an unknown version byte is `UNSUPPORTED_VERSION` from a read |

The parse surfaces do not throw for malformed data, so a caller that wrapped
the old ones in `try`/`catch` reads the status instead. `OwidException` is
still raised for the caller's own mistakes, such as an invalid creator
domain, a null payload, or a field that cannot be serialized.

## Interface

- `Owid` holds the version, domain, date to the minute in UTC, payload bytes,
  and signature bytes, all read only.
  - `Owid.tryParse` and `Owid.tryParseBytes` read a signed OWID and report
    why rather than throwing.
  - `asBase64` and `asByteArray` serialize a signed OWID.
  - `payloadAsString` decodes the payload as UTF-8. `payloadAsPrintable`
    returns zero padded lower case hexadecimal with no separator.
    `payloadAsBase64` returns the payload as base 64. `getPayloadLength`
    reports the payload size without copying it.
  - `verifyWithCrypto` and `verifyWithPublicKey` return whether the signature,
    covering this OWID and any others provided, is valid.
  - `verifyDetailed` and `verifyDetailedWithPublicKey` answer the same
    question with a status, keeping a key that could not be used apart from a
    signature that does not match.
  - `ageMinutes` returns the minutes elapsed since creation.
- `Crypto` holds the keys.
  - `Crypto.generate` creates a new P-256 key pair.
  - `Crypto.newSignOnly` imports a PKCS#8 private key PEM. The public key is
    derived so the instance can also verify.
  - `Crypto.newVerifyOnly` imports an SPKI public key PEM.
  - `signByteArray` returns the 64 byte signature. `verifyByteArray` returns
    whether a signature is valid.
  - `publicKeyPem` and `privateKeyPem` export the keys as PEM text.
  - An empty, whitespace, or null PEM is rejected with a clear message rather
    than an opaque cryptography error.
- `Creator` binds a domain to a signing `Crypto`.
  - `createString` and `createBytes` create a complete signed OWID, setting
    the domain to the creator domain, the date to the current time and the
    version to the current version. Both take an optional list of other OWIDs
    to cover with the same signature.
- `Endpoints` provides framework agnostic helpers for the well known end
  points.
  - `creatorResponse` returns JSON with the fields `domain`, `name`,
    `publicKeySPKI`, and `contractURL`. The path is `/owid/api/v{n}/creator`.
  - `publicKeyResponse` returns the PEM. The path is
    `/owid/api/v{n}/public-key` with a `format` parameter of `spki` or `pkcs`.

## Data structure notes

A signed OWID serializes to bytes in this exact order. Multi byte integers are
little endian, except the version 1 date.

| Field          | Bytes               | Description                                                  |
|----------------|---------------------|--------------------------------------------------------------|
| Version        | 1                   | The byte version of the OWID. Always the first byte.         |
| Domain         | length + 1          | Domain associated with the creator, null (0) terminated.     |
| Date           | 4 (2 for version 1) | Minutes elapsed since 2020-01-01 UTC as an unsigned integer. |
| Payload length | 4                   | Number of bytes that form the payload.                       |
| Payload        | variable            | Bytes that form the payload, if any.                         |
| Signature      | 64                  | ECDSA P-256 signature as the r and s values concatenated.    |

Version 1 stored the date as a two byte big endian count of hours since the
base date. Version 2 and version 3 store a four byte little endian count of
minutes. Versions 1 and 2 are deprecated and supported for reading existing
data only.

The signature is stored as 64 raw bytes, the 32 byte big endian r value
followed by the 32 byte big endian s value (IEEE P1363 format). It is not
ASN.1 DER. The data covered by the signature is this OWID without its
signature, followed by the complete bytes, including signature, of each other
OWID in the order provided when signing.

An empty OWID is written as the single byte `0x00`. It marks an absent
optional OWID inside a larger byte array.

Base 64 decoding accepts the standard alphabet with or without the trailing
padding, and skips line breaks and spaces. Anything else in the string is
reported as `INVALID_BASE64`. Encoding always emits padding.

## Testing

Run the test suite with Maven.

```
mvn test
```

The tests round trip the canonical wire format vectors byte for byte, verify
cross language signed fixtures including the chained case, confirm that a
flipped signature byte fails verification, and cover the binary write
helpers, the crypto, the creator, and the end point helpers. They also cover
the parse contract, being every status the reading surfaces report together
with a run of malformed buffers that must never throw, and the construction
boundary, which is checked from a package outside the library because a check
made from inside it would measure nothing.

## License

Apache License 2.0. See the [LICENSE](LICENSE) file.
