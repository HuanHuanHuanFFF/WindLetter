# Phase 2 Signed Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Every production change follows RED -> GREEN -> REFACTOR, and every independently testable closed loop is committed separately.

**Goal:** Complete the real `public x X25519 x signed x multi-recipient` WindLetter flow with strict flattened JWS, exact Ed25519 signing bytes, trusted signing-key resolution, authenticated sender identity, negative tests, and full unsigned regression.

**Architecture:** Keep the proven stage-one outer/X25519 path unchanged and add parallel signed-only classes. Reuse the outer parser, recipient builder/router, AAD, binding, X25519/HKDF, A256KW, A256GCM, and writer; add a strict signed inner codec and trusted Ed25519 identity boundary. Do not introduce Hybrid, obfuscation, Armor, the high-level API facade, or a generic future framework in this phase.

**Tech Stack:** Java 17, Maven reactor, Jackson strict JSON, RFC 8785 JCS, RFC 7638/RFC 8037 key thumbprints, Bouncy Castle Ed25519/X25519/A256KW/A256GCM, JUnit 5.

---

## 0. Execution status and project constraints

- Phase status: complete (2026-07-17); stopped at the phase gate awaiting user confirmation for Phase 3.
- Branch: `spike/demo-v0`.
- Phase baseline HEAD: `3659d6213ebbef0a8642fff97d065b12be1a4574`.
- Baseline verification: JDK 17.0.16, `mvn -q test` exit code 0; 285 tests, 0 failures, 0 errors, 0 skipped.
- Existing `docs/README.md` line-ending-only worktree marker is excluded from every phase commit.
- No push is authorized by entering this phase. Pushing still requires a separate user request.
- Commit rule: one independently testable closed loop per commit. Do not bundle the whole phase into one commit.
- Demo quality gate:
  - protocol, cryptographic, authentication, P0, and P1 defects block the relevant phase capability;
  - P2 defects may be deferred;
  - every deferred P2 must be listed in the final phase report with impact and follow-up advice.

### 0.1 Final closure evidence

- Runtime: Microsoft OpenJDK 17.0.16.
- Task 5 focused gate: 15 tests, 0 failures, 0 errors, 0 skipped.
- Protocol module after Task 5: 345 tests, 0 failures, 0 errors, 0 skipped.
- Final `mvn -q clean test`: 44 suites and 435 tests, 0 failures, 0 errors, 0 skipped.
- Final spec review and code/security review: PASS; no unresolved P0/P1 finding.
- Task 5 proved the existing production flow without modifying production code.
- `docs/README.md` remained excluded as pre-existing line-ending-only worktree noise.

### 0.2 Authority order

1. Current source and tests describe what is implemented.
2. `docs/Wind Letter v1.0协议.md` defines formal protocol intent.
3. `docs/dev/01-demo-first-overall-implementation-plan.md` freezes Demo interpretations where the formal document is internally inconsistent.
4. This document freezes the exact Phase 2 implementation profile.

## 1. Phase boundary

### 1.1 Included

- `public` outer mode.
- `key_alg="X25519"`.
- `outer.protected.cty="wind+jws"`.
- Strict flattened signed inner wire.
- RFC 7638 + RFC 8037 Ed25519 signing kid.
- Exact `ASCII(protected_b64 + "." + payload_b64)` signing and verification input.
- Real Ed25519 signing and verification through `Ed25519Crypto`.
- Trusted signing-key resolution with a trusted identity ID.
- `SIGNED_VALID` result with authenticated signing identity.
- One to 32 real recipients, including first/middle/last routing proof.
- Binding-before-signature verification ordering.
- Authenticated malicious-inner fixtures made with real GCM re-encryption.
- All stage-one unsigned tests as regression gates.

### 1.2 Excluded

- `X25519ML-KEM-768`.
- `obfuscation`, rid, decoys, padding, and shuffling.
- Armor.
- Concrete `windletter-api` Sender/Receiver facade orchestration.
- `windletter-testkit` vector publication.
- A generic sender/receiver framework or broad signed/unsigned outer-flow refactor.
- Formal protocol-document cleanup that does not affect executable correctness.

## 2. Frozen protocol profile

### 2.1 Outer profile

Decoded protected header must be exactly the stage-one public/X25519 profile except for signed content type:

```json
{
  "typ": "wind+jwe",
  "cty": "wind+jws",
  "ver": "1.0",
  "wind_mode": "public",
  "enc": "A256GCM",
  "key_alg": "X25519",
  "kid": {
    "x25519": "BASE64URL(RFC7638 sender X25519 kid)"
  }
}
```

Recipient entries remain:

```json
{
  "kid": {
    "x25519": "BASE64URL(RFC7638 recipient X25519 kid)"
  },
  "encrypted_key": "BASE64URL(A256KW(CEK))"
}
```

For this profile `ek` and `kid.mlkem768` are forbidden.

### 2.2 Actual signed inner wire

The GCM plaintext is a flattened JWS object, not the protocol document's expanded debugging view:

```json
{
  "protected": "BASE64URL(JCS(inner protected header))",
  "payload": "BASE64URL(JCS(inner payload))",
  "signature": "BASE64URL(64-byte Ed25519 signature)"
}
```

The root exact field set is `protected`, `payload`, `signature`. Object-valued `protected`/`payload`, `header`, `signatures`, or any other root member are rejected.

### 2.3 Signed protected header

The exact decoded field set is:

```json
{
  "typ": "wind+jws",
  "alg": "EdDSA",
  "kid": "BASE64URL(32-byte Ed25519 JWK thumbprint)",
  "ts": 1731800000,
  "wind_id": "123e4567-e89b-42d3-a456-426614174000",
  "jwe_protected_hash": "BASE64URL(32 bytes)",
  "jwe_recipients_hash": "BASE64URL(32 bytes)"
}
```

- `typ` is mandatory even though one formal-protocol subsection accidentally omits it; the main examples and approved overall plan require it.
- `alg` must equal `EdDSA`, but implementation always calls pure Ed25519. The wire header never chooses a provider or another EdDSA variant.
- `kid` is canonical unpadded Base64URL and decodes to exactly 32 bytes.
- `ts` is an integral JSON number in `0..9007199254740991`.
- `wind_id` is a canonical lowercase UUID v4.
- Both binding values are canonical Base64URL of exactly 32 bytes.

### 2.4 Signed payload

The decoded payload exact field sets and semantics are identical to the unsigned payload:

```json
{
  "meta": {
    "content_type": "application/octet-stream",
    "original_size": 3
  },
  "body": {
    "data": "AAEC"
  }
}
```

- `content_type` is a non-blank string.
- `original_size` is integral, non-negative, within `ProtocolLimits.MAX_PAYLOAD_BYTES`, and equals decoded data length.
- `data` is canonical Base64URL; empty string is allowed only for zero-length payload.

### 2.5 Exact bytes

Sender construction is deterministic:

```text
outer_protected_bytes = JCS(outer protected JSON)
recipients_bytes      = JCS(final recipients array)

outer.protected = Base64URL(outer_protected_bytes)
outer.aad       = Base64URL(recipients_bytes)

jwe_protected_hash  = SHA256(outer_protected_bytes)
jwe_recipients_hash = SHA256(recipients_bytes)

header_bytes  = JCS(signed protected header JSON)
payload_bytes = JCS(signed payload JSON)

protected_b64 = Base64URL(header_bytes)
payload_b64   = Base64URL(payload_bytes)

signing_input = ASCII(protected_b64 + "." + payload_b64)
signature     = Ed25519.Sign(signing_private_key, signing_input)

inner_bytes = JCS({
  "protected": protected_b64,
  "payload": payload_b64,
  "signature": Base64URL(signature)
})

gcm_aad = ASCII(outer.protected + "." + outer.aad)
```

Receiver verification always uses the exact received `protected` and `payload` strings. It must not decode, canonicalize, and re-encode them before verification.

Sender emits JCS for header, payload, and flattened wrapper. Receiver requires strict JSON shape and canonical Base64URL, but does not reject an otherwise valid wrapper merely because whitespace/member order differs; GCM and the exact JWS signing input already authenticate received bytes. Formal documentation of this receiver-side canonical-acceptance policy is tracked as P2.

### 2.6 Ed25519 signing kid

```text
x = Base64URL(ed25519_public_key_32)
jwk = JCS({"crv":"Ed25519","kty":"OKP","x":x})
kid = Base64URL(SHA256(jwk))
```

Fixed test vector:

```text
public key = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
x          = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
jwk        = {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
kid        = kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

### 2.7 Trusted identity boundary

- The signing-key resolver is local and trusted; a wire kid is never treated as a URL or remote key-fetch instruction.
- A resolved record contains `identityId`, `signingKid`, and a 32-byte Ed25519 public key.
- Receiver validates that the record kid equals the requested wire kid and that `Ed25519KeyId.derive(publicKey)` equals the wire kid.
- The authenticated business identity comes only from this trusted Ed25519 record and is released only after verification succeeds.
- The outer X25519 sender kid is needed for encryption key agreement; it is not exposed as signature-authenticated business identity.
- Binding the X25519 and Ed25519 keys to the same account is an identity-store/API policy for Phase 6. Phase 2 makes no false same-principal claim.

### 2.8 Receiver gate order

```text
strict outer parse/profile
  -> AAD verify
  -> recipient route
  -> outer sender X25519 key resolve and kid bind
  -> X25519/HKDF KEK
  -> A256KW CEK unwrap
  -> A256GCM decrypt/tag verify
  -> strict flattened JWS decode
  -> cty/typ and alg validation
  -> inner/outer binding verify
  -> trusted Ed25519 key resolve and kid bind
  -> exact-segment Ed25519 verify
  -> payload + SIGNED_VALID + trusted identity
```

No signed failure returns a payload or authenticated identity. Only no recipient match is `NOT_FOR_ME`; unknown signing kid is a signature failure.

### 2.9 Internal error mapping

| Condition | Internal `ErrorCode` |
|---|---|
| Invalid JSON syntax, duplicate member, wrong JSON type, trailing content | `MALFORMED_WIRE` |
| Missing/unknown field, invalid fixed value/length/Base64URL/profile | `INVALID_FIELD` or existing outer profile code |
| No recipient match | `NOT_FOR_ME` |
| AAD mismatch | `AAD_MISMATCH` |
| KEK/unwrap failure | `KEY_UNWRAP_FAILED` |
| GCM/tag failure | `GCM_AUTH_FAILED` |
| Binding mismatch | `BINDING_FAILED` |
| Unknown signing kid or cryptographically invalid signature | `SIGNATURE_INVALID` |
| Resolver/provider contract failure | `INTERNAL_ERROR` |

The future API facade must collapse all wire failures except `NOT_FOR_ME` to public `INVALID_MESSAGE`. Phase 2 preserves fine codes only for tests and controlled diagnostics.

## 3. File map

### New production files

- `windletter-protocol/src/main/java/com/windletter/protocol/key/Ed25519KeyId.java`
  - RFC 7638 + RFC 8037 Ed25519 public-key thumbprint.
- `windletter-protocol/src/main/java/com/windletter/protocol/inner/SignedInnerCodec.java`
  - Deterministic JCS preparation/assembly and strict flattened JWS decoding.
- `windletter-protocol/src/main/java/com/windletter/protocol/signature/TrustedEd25519Key.java`
  - Trusted identity ID, signing kid, and defensive 32-byte public-key snapshot.
- `windletter-protocol/src/main/java/com/windletter/protocol/signature/Ed25519VerificationKeyResolver.java`
  - Local trusted lookup by signing kid.
- `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolSenderIdentity.java`
  - Authenticated identity ID and verified signing kid; no raw key material.
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519SignedSender.java`
  - Real public/X25519/signed multi-recipient sender.
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519SignedReceiver.java`
  - Real public/X25519/signed receiver with trusted verification.

### Existing production file modified

- `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolAuthenticationStatus.java`
  - Add `SIGNED_VALID`; keep `UNSIGNED` unchanged.

### New test files

- `windletter-protocol/src/test/java/com/windletter/protocol/key/Ed25519KeyIdTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/inner/SignedInnerCodecTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/signature/TrustedEd25519KeyTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedSenderTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedReceiverTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedMultiRecipientE2ETest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedTamperE2ETest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/SignedProtocolFlowTestFixtures.java`

No POM dependency change is expected.

## 4. Closed-loop commits

| Commit | Closed loop | Focused gate |
|---|---|---|
| `42f8ac4` | Phase 2 executable plan | plan self-review and diff check |
| `e304158` | RFC 7638 Ed25519 kid + trusted key records | key/signature model tests |
| `7e27512` | Strict flattened signed inner codec | `SignedInnerCodecTest` |
| `b39384a` | Real public/X25519 signed Sender | sender tests plus existing unsigned sender tests |
| `7e7918b` | Trusted signed Receiver | receiver tests plus existing unsigned receiver tests |
| this closure commit | Signed adversarial E2E and phase gate | 15 focused, 345 protocol, and 435 reactor tests; plan status update |

No commit includes `docs/README.md`, build output, or unrelated cleanup.

## 5. Task 1: RFC 7638 Ed25519 kid and trusted identity records

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/key/Ed25519KeyIdTest.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/key/Ed25519KeyId.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/signature/TrustedEd25519KeyTest.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/signature/TrustedEd25519Key.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/signature/Ed25519VerificationKeyResolver.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolSenderIdentity.java`
- Modify: `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolAuthenticationStatus.java`

- [x] **Step 1: Write failing exact-vector and validation tests**

```java
assertEquals(
    "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
    Ed25519KeyId.derive(hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
);
assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(null));
assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(new byte[31]));
assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(new byte[33]));
```

Trusted material tests require non-blank IDs, a canonical 32-byte kid, a 32-byte public key, and defensive copies. `ProtocolSenderIdentity` requires non-blank identity and signing kid. Enum test locks values to `UNSIGNED`, `SIGNED_VALID` without removing stage-one behavior.

- [x] **Step 2: Run RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=Ed25519KeyIdTest,TrustedEd25519KeyTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation/test failure because the new production types do not exist.

- [x] **Step 3: Implement the minimal records and thumbprint**

`Ed25519KeyId.derive` mirrors `X25519KeyId` but uses `crv="Ed25519"`. `TrustedEd25519Key` snapshots the key and validates that its signing kid is canonical Base64URL decoding to 32 bytes. The receiver, not the record constructor, performs the final key-to-kid derivation check so resolver contract failures can be mapped deliberately.

- [x] **Step 4: Run GREEN and regression**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=Ed25519KeyIdTest,TrustedEd25519KeyTest,UnsignedInnerCodecTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit code 0.

- [x] **Step 5: Commit only this closed loop**

```text
feat(protocol): add trusted Ed25519 key identity
```

## 6. Task 2: Strict flattened signed inner codec

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/inner/SignedInnerCodecTest.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/inner/SignedInnerCodec.java`

### 6.1 Required public shape

```java
public final class SignedInnerCodec {
    public Prepared prepare(Message message);
    public byte[] assemble(Prepared prepared, byte[] signature);
    public Decoded decode(byte[] innerBytes);

    public record Message(
        String messageId,
        long timestamp,
        ProtocolPayload payload,
        OuterBinding.Hashes binding,
        String signingKid
    ) {}

    public static final class Prepared implements AutoCloseable {
        public String protectedValue();
        public String payloadValue();
        public byte[] signingInput();
        public void close();
    }

    public static final class Decoded implements AutoCloseable {
        public Message message();
        public byte[] signingInput();
        public byte[] signature();
        public void close();
    }
}
```

`Prepared` and `Decoded` return defensive array copies and clear their internal signing-input/signature arrays on close. They never own or close a crypto handle.

- [x] **Step 1: Write failing deterministic-byte tests**

Tests hard-code the expected canonical header JSON order:

```json
{"alg":"EdDSA","jwe_protected_hash":"...","jwe_recipients_hash":"...","kid":"...","ts":1731800000,"typ":"wind+jws","wind_id":"123e4567-e89b-42d3-a456-426614174000"}
```

and payload order:

```json
{"body":{"data":"AAEC"},"meta":{"content_type":"application/octet-stream","original_size":3}}
```

The test asserts the exact prepared strings and:

```java
assertArrayEquals(
    (prepared.protectedValue() + "." + prepared.payloadValue()).getBytes(StandardCharsets.US_ASCII),
    prepared.signingInput()
);
```

- [x] **Step 2: Run RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=SignedInnerCodecTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure because `SignedInnerCodec` does not exist.

- [x] **Step 3: Implement deterministic prepare/assemble and round-trip decode**

Use `JcsCanonicalizer`, `Base64Url`, `StrictJson`, and `ProtocolLimits`; do not use a JOSE library. `decode` reconstructs signing input directly from the two received strings.

- [x] **Step 4: Add the strict negative matrix one group at a time**

Each new group is first observed failing, then made green:

- root/protected/payload duplicate members;
- root/protected/payload unknown, missing, null, and wrong-type members;
- trailing content and malformed/non-UTF-8 JSON;
- padding, whitespace, invalid alphabet, and non-canonical Base64URL;
- `typ != wind+jws`, `alg != EdDSA`;
- kid/hash 31 or 33 bytes; signature 63 or 65 bytes;
- invalid timestamp and UUID;
- blank content type, size mismatch, payload/inner limit overflow;
- binary and zero-length payload;
- defensive copying and idempotent close.

- [x] **Step 5: Run codec GREEN and unsigned regression**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=SignedInnerCodecTest,UnsignedInnerCodecTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit code 0.

- [x] **Step 6: Commit only the codec closed loop**

```text
feat(protocol): add strict flattened signed inner codec
```

## 7. Task 3: Public X25519 signed Sender

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedSenderTest.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519SignedSender.java`

### 7.1 Request and result

```java
public record Request(
    ProtocolPayload payload,
    String messageId,
    long timestamp,
    X25519PrivateKeyHandle senderEncryptionPrivateKey,
    Ed25519PrivateKeyHandle senderSigningPrivateKey,
    List<byte[]> recipientPublicKeys
) {}

public record Result(WindLetter message, String wireJson) {}
```

Both private handles are borrowed. The flow derives the signing kid from `senderSigningPrivateKey.publicKey()` and never accepts a caller-supplied signing kid.

- [x] **Step 1: Write a failing real-crypto sender test**

The test uses Bouncy Castle primitives, decrypts the output using the known recipient, decodes the flattened JWS, and independently verifies:

```java
assertEquals("wind+jws", result.message().protectedHeader().cty());
assertTrue(ed25519.verify(
    signingHandle.publicKey(),
    decoded.signingInput(),
    decoded.signature()
));
assertEquals(Ed25519KeyId.derive(signingHandle.publicKey()), decoded.message().signingKid());
```

- [x] **Step 2: Run RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519SignedSenderTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure because the signed sender does not exist.

- [x] **Step 3: Implement the sender by preserving stage-one ordering**

```text
generate CEK/IV
  -> build cty=wind+jws protected header
  -> build all recipients with one CEK
  -> compute AAD/binding from final recipients
  -> derive Ed25519 kid
  -> prepare exact signed inner
  -> real Ed25519 sign
  -> assemble flattened inner
  -> real A256GCM encrypt
  -> write outer JSON
```

Finally clear sender public-key snapshots, signing public-key snapshot, CEK, IV, signing input, signature, inner bytes, and GCM AAD. Do not close either borrowed handle.

- [x] **Step 4: Add request/provider/ownership tests RED then GREEN**

- null and invalid request values;
- 1..32 recipients and duplicate kid rejection inherited from the same request rules;
- bad provider signature length;
- provider failure before and after signing;
- fresh CEK/IV per call;
- borrowed handles remain open after success/failure;
- every mutable temporary owned by the flow is zeroed on success/failure.

- [x] **Step 5: Run sender and stage-one sender regression**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519SignedSenderTest,PublicX25519UnsignedSenderTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit code 0.

- [x] **Step 6: Commit only the sender closed loop**

```text
feat(protocol): add public X25519 signed sender
```

## 8. Task 4: Trusted Public X25519 signed Receiver

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedReceiverTest.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519SignedReceiver.java`

### 8.1 Request and result

```java
public record Request(
    String wireJson,
    SenderX25519PublicKeyResolver senderEncryptionKeys,
    Ed25519VerificationKeyResolver senderSigningKeys,
    List<X25519PrivateKeyHandle> recipientPrivateKeys
) {}

public record Result(
    ProtocolPayload payload,
    String messageId,
    long timestamp,
    ProtocolAuthenticationStatus authenticationStatus,
    ProtocolSenderIdentity authenticatedSender
) {}
```

Successful construction requires `SIGNED_VALID` and non-null authenticated sender. There is no failure Result; failures throw `ProtocolException`, so payload/identity cannot leak through a partial object.

- [x] **Step 1: Write failing trusted-success and unknown-key tests**

The success resolver returns:

```java
new TrustedEd25519Key(
    "sender-identity-1",
    Ed25519KeyId.derive(signingPublicKey),
    signingPublicKey
)
```

Success asserts restored binary payload, message ID, timestamp, `SIGNED_VALID`, trusted identity ID, verified signing kid, and borrowed handles still open. Empty resolver must fail with `SIGNATURE_INVALID` and never return a Result.

- [x] **Step 2: Run RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519SignedReceiverTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure because the signed receiver does not exist.

- [x] **Step 3: Implement the exact receiver gate order from section 2.8**

The resolver is not called before strict outer/AAD/routing/GCM/inner/binding gates. After resolution, snapshot the public key, check record kid equality, rederive the RFC 7638 kid, and verify the exact received signing input.

- [x] **Step 4: Add receiver error/ownership tests RED then GREEN**

- unrelated recipient -> `NOT_FOR_ME` without signing resolver call;
- unknown signing kid -> `SIGNATURE_INVALID`;
- wrong key / `verify=false` -> `SIGNATURE_INVALID`;
- resolver returns null Optional, throws, or returns mismatched trusted record -> `INTERNAL_ERROR` internally;
- wrong outer profile and outer/inner `cty`/`typ` mismatch -> invalid message code;
- binding failure happens before resolver/verify;
- no borrowed X25519 handle is closed;
- KEK, CEK, GCM AAD, decrypted inner, signing input/signature/public-key snapshots are cleared on success and every failure path.

- [x] **Step 5: Run receiver and unsigned regression**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519SignedReceiverTest,PublicX25519UnsignedReceiverTest,PublicKidRouterTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit code 0.

- [x] **Step 6: Commit only the receiver closed loop**

```text
feat(protocol): verify trusted Ed25519 sender identity
```

## 9. Task 5: Multi-recipient signed E2E and adversarial closure

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/SignedProtocolFlowTestFixtures.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedMultiRecipientE2ETest.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519SignedTamperE2ETest.java`
- Modify only if a newly failing test proves a defect in the Phase 2 production files.
- Modify after all gates pass: `docs/dev/03-phase-2-signed-authentication-plan.md`
- Modify after all gates pass: `docs/dev/01-demo-first-overall-implementation-plan.md`

- [x] **Step 1: Add three-recipient wire-only E2E**

For first, middle, and last recipients, pass only the same serialized JSON string, that recipient's private handle, outer sender resolver, and trusted signing resolver. Assert identical binary/empty payload recovery plus `SIGNED_VALID` and the trusted identity. An unrelated recipient remains `NOT_FOR_ME`.

- [x] **Step 2: Add authenticated binding tamper fixtures**

Use deterministic known CEK/IV, construct an otherwise strict signed inner with one wrong binding, sign it with the real signing key, and perform real A256GCM re-encryption. Expected code is `BINDING_FAILED`, and the signing resolver must not be called.

- [x] **Step 3: Add authenticated signature tamper fixtures**

Keep correct binding and strict inner shape, but use one of:

- flipped 64-byte signature;
- protected/payload segment changed without resigning;
- a valid signature and kid from an unknown real Ed25519 key.

Re-encrypt with real GCM so GCM passes. Expected code is `SIGNATURE_INVALID`.

- [x] **Step 4: Add strict mismatch and failure-order cases**

- signed outer plus unsigned/incorrect inner `typ`;
- wrong `alg`;
- missing/extra signed field;
- bad kid/signature length;
- outer recipient/AAD/protected/IV/ciphertext/tag mutations retain the stage-one gate ordering.

- [x] **Step 5: Run focused and module tests**

```powershell
mvn -q -pl windletter-protocol -am test
```

Expected: exit code 0; all stage-one unsigned and Phase 2 signed tests pass.

- [x] **Step 6: Run full JDK 17 reactor gate**

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q clean test
git diff --check
```

Expected: both commands exit 0, no skipped/disabled tests are introduced, and `docs/README.md` remains excluded.

- [x] **Step 7: Independent reviews**

- Spec review checks every requirement and exact byte formula.
- Code/security review checks P0/P1, error-oracle boundaries, ownership, zeroization, and test authenticity.
- Critical/Important/P0/P1 findings are fixed and re-reviewed before completion.
- P2 findings are recorded rather than silently discarded.

- [x] **Step 8: Update phase status and commit the closure**

Update this document with exact test counts, review result, commit list, and P2 debt. Mark Phase 2 complete in the overall plan only after the full gate passes.

```text
test(protocol): close signed authentication phase
```

## 10. P0/P1 completion gate

- [x] Actual inner is strict flattened JWS, never the expanded debugging view.
- [x] Sender header, payload, and wrapper bytes are deterministic and locked by exact tests.
- [x] Receiver verifies exact received encoded segments.
- [x] Ed25519 kid follows the fixed RFC 7638/RFC 8037 vector.
- [x] `typ="wind+jws"`, `alg="EdDSA"`, exact fields, Base64URL, lengths, UUID, timestamp, and payload invariants are strict.
- [x] Trusted signing key is 32 bytes, record kid matches requested kid, and rederived kid matches the public key.
- [x] Authenticated identity originates only from the verified trusted signing-key record.
- [x] Binding is checked before signature resolution/verification.
- [x] Unknown kid, wrong key, bad signature, and mismatch never degrade to unsigned or return payload/identity.
- [x] Only recipient no-match is `NOT_FOR_ME`.
- [x] Three real recipients recover the same signed message from the same wire JSON.
- [x] Binding/signature targeted tests use real GCM re-encryption and reach the intended gate.
- [x] Borrowed X25519 and Ed25519 handles remain open; owned secret/temporary arrays are cleared best-effort.
- [x] Every stage-one unsigned test remains green.
- [x] JDK 17 full reactor test and `git diff --check` pass.
- [x] No unresolved P0/P1 review finding remains.

## 11. Deferred P2 register

These items do not block Phase 2 unless implementation reveals a protocol/security impact:

1. Deduplicate parallel signed/unsigned outer-flow orchestration after more profiles expose stable common boundaries.
2. Publish Ed25519 and signed-wire vectors through `windletter-testkit` in the final testkit phase.
3. Add more RFC 8032 vectors beyond the already implemented vector 1.
4. Clarify in the formal protocol that actual inner wire is flattened JWS and the object form is only an expanded view.
5. Correct the formal protocol's missing signed `typ`, section-number typo, and missing explicit RFC 7515/RFC 8037 references.
6. Specify formally whether receivers must reject non-JCS but strict/valid decoded header, payload, or wrapper JSON; this Demo sender emits JCS while receiver verifies exact encoded segments.
7. Specify `content_type` grammar and a dedicated field-length cap; current Demo uses non-blank plus total resource limits.
8. Document Java/Jackson immutable-string copies as outside best-effort mutable-byte zeroization.
9. Resolve API-only dormant invariants before Phase 6 activates the facade:
   - `VerificationKeyMaterial` exact 32-byte key and kid binding;
   - `SigningIdentityLease` supplied kid binding;
   - `DecryptResult` status/payload/identity/error consistency;
   - same-principal policy across encryption and signing identities.
10. Reassess profile-dependent effective maximum payload size caused by flattened JWS Base64 expansion under the current 12 MiB inner limit.
11. Give `byte[]`-backed value records such as `TrustedEd25519Key` content-based `equals`/`hashCode` semantics if later code relies on value equality.
12. Add direct tests for remaining provider/resolver contract edges and explicit cross-identity isolation; production validation exists, but some cases currently rely on adjacent regression suites.
13. Define an explicit lifecycle if sender request objects retain recipient public-key snapshots longer than one call; the snapshots are public material, not secrets.
14. Tighten size-limit test intent: distinguish decoded payload caps from total signed-inner caps, and directly cover the assembled-output cap.
15. In the extremely unlikely platform-exception path inside X25519 kid derivation, clear the local sender public-key clone before propagation; this is public material and normal JDK 17 execution cannot reach the gap.
16. Keep the deterministic Task 5 random source test-only: it deliberately reuses a known CEK/IV to construct authenticated malicious fixtures, and unconsumed cloned values are only GC-cleared if the sender exits exceptionally before requesting both values.
17. Strengthen the unknown-signer fixture with an independent positive verification of the unrelated signature and an explicit assertion of the requested unrelated kid.
18. Task 5 E2E relies on the dedicated Task 3/4 tracking-provider suites for exhaustive secret zeroization and borrowed-handle ownership; keep those suites paired in future refactors.

Every still-open P2 item must appear in the Phase 2 completion report.
