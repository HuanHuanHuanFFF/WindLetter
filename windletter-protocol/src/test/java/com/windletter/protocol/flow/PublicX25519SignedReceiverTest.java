package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicX25519SignedReceiverTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final String IDENTITY_ID = "sender-identity-1";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void receivesRealSignedSenderWireAndReleasesOnlyTrustedIdentity() {
        try (RealFixture fixture = new RealFixture()) {
            PublicX25519SignedReceiver.Result result = fixture.receiver().receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            );

            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID, result.authenticationStatus());
            assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
            assertEquals(fixture.signingKid, result.authenticatedSender().signingKid());
            assertEquals(fixture.payload.contentType(), result.payload().contentType());
            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void unknownSigningKidIsSignatureInvalidAndReturnsNoResult() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicReference<String> requestedKid = new AtomicReference<>();
            ProtocolException failure = assertThrows(ProtocolException.class, () -> fixture.receiver().receive(
                    fixture.request(kid -> {
                        requestedKid.set(kid);
                        return Optional.empty();
                    }, List.of(fixture.second))
            ));

            assertEquals(ErrorCode.SIGNATURE_INVALID, failure.errorCode());
            assertEquals(fixture.signingKid, requestedKid.get());
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void unrelatedRecipientIsNotForMeBeforeEitherSenderResolver() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger encryptionResolverCalls = new AtomicInteger();
            AtomicInteger signingResolverCalls = new AtomicInteger();
            PublicX25519SignedReceiver.Request request = new PublicX25519SignedReceiver.Request(
                    fixture.wire,
                    kid -> {
                        encryptionResolverCalls.incrementAndGet();
                        return Optional.of(fixture.senderEncryptionKey.publicKey());
                    },
                    kid -> {
                        signingResolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    },
                    List.of(fixture.unrelated)
            );

            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(request));
            assertEquals(0, encryptionResolverCalls.get());
            assertEquals(0, signingResolverCalls.get());
            assertEquals(32, fixture.unrelated.publicKey().length);
        }
    }

    @Test
    void malformedOuterAndAadMismatchPrecedeRoutingAndBothResolvers() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger encryptionResolverCalls = new AtomicInteger();
            AtomicInteger signingResolverCalls = new AtomicInteger();
            com.windletter.protocol.signature.Ed25519VerificationKeyResolver signingResolver = kid -> {
                signingResolverCalls.incrementAndGet();
                return Optional.of(fixture.trustedSigningKey());
            };
            SenderX25519PublicKeyResolver encryptionResolver = kid -> {
                encryptionResolverCalls.incrementAndGet();
                return Optional.of(fixture.senderEncryptionKey.publicKey());
            };

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    new PublicX25519SignedReceiver.Request(
                            "{", encryptionResolver, signingResolver, List.of(fixture.unrelated)
                    )
            ));

            ObjectNode aadTampered = (ObjectNode) JSON.readTree(fixture.wire);
            aadTampered.put("aad", Base64Url.encode(new byte[]{1}));
            assertCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    new PublicX25519SignedReceiver.Request(
                            aadTampered.toString(),
                            encryptionResolver,
                            signingResolver,
                            List.of(fixture.unrelated)
                    )
            ));

            assertEquals(0, encryptionResolverCalls.get());
            assertEquals(0, signingResolverCalls.get());
        }
    }

    @Test
    void falseVerificationIsSignatureInvalid() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingEd25519 rejecting = new RecordingEd25519(fixture.ed25519, false, null);
            PublicX25519SignedReceiver receiver = fixture.receiver(rejecting);

            assertCode(ErrorCode.SIGNATURE_INVALID, () -> receiver.receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            ));
            assertEquals(1, rejecting.verifyCalls);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void realBouncyCastleVerificationRejectsAnAuthenticatedTamperedSignature() {
        try (RealFixture fixture = new RealFixture()) {
            String maliciousWire = fixture.authenticatedTamperedSignatureWire();

            assertCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver().receive(
                    fixture.request(
                            kid -> Optional.of(fixture.trustedSigningKey()),
                            List.of(fixture.second),
                            maliciousWire
                    )
            ));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void signingResolverContractFailuresAreInternal() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(kid -> null, List.of(fixture.second))
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(kid -> {
                        throw new IllegalStateException("resolver unavailable");
                    }, List.of(fixture.second))
            ));

            byte[] unrelatedPublic = fixture.unrelatedSigningKey.publicKey();
            String unrelatedKid = Ed25519KeyId.derive(unrelatedPublic);
            try {
                TrustedEd25519Key mismatchedKid = new TrustedEd25519Key(
                        "other-identity", unrelatedKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                        fixture.request(kid -> Optional.of(mismatchedKid), List.of(fixture.second))
                ));

                TrustedEd25519Key mismatchedPublic = new TrustedEd25519Key(
                        IDENTITY_ID, fixture.signingKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                        fixture.request(kid -> Optional.of(mismatchedPublic), List.of(fixture.second))
                ));
            } finally {
                java.util.Arrays.fill(unrelatedPublic, (byte) 0);
            }
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void verificationProviderFailureIsInternal() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingEd25519 failing = new RecordingEd25519(
                    fixture.ed25519,
                    true,
                    new com.windletter.crypto.api.CryptoOperationException("verification unavailable")
            );

            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver(failing).receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            ));
            assertEquals(1, failing.verifyCalls);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void wrongOuterContentTypeIsRejectedBeforeRoutingOrSigningResolution() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            ObjectNode root = (ObjectNode) JSON.readTree(fixture.wire);
            byte[] protectedBytes = Base64Url.decodeCanonical(
                    root.get("protected").textValue(), "test.protected"
            );
            ObjectNode protectedNode = (ObjectNode) JSON.readTree(protectedBytes);
            protectedNode.put("cty", "wind+inner");
            root.put("protected", Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
            java.util.Arrays.fill(protectedBytes, (byte) 0);
            AtomicInteger signingResolverCalls = new AtomicInteger();

            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> fixture.receiver().receive(
                    new PublicX25519SignedReceiver.Request(
                            root.toString(),
                            kid -> Optional.of(fixture.senderEncryptionKey.publicKey()),
                            kid -> {
                                signingResolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.unrelated)
                    )
            ));
            assertEquals(0, signingResolverCalls.get());
        }
    }

    @Test
    void signedOuterRejectsAuthenticatedUnsignedInnerBeforeSigningResolution() {
        try (RealFixture fixture = new RealFixture()) {
            byte[] unsignedInner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    MESSAGE_ID,
                    TIMESTAMP,
                    fixture.payload,
                    fixture.binding()
            ));
            String maliciousWire;
            try {
                maliciousWire = fixture.authenticatedWire(unsignedInner);
            } finally {
                java.util.Arrays.fill(unsignedInner, (byte) 0);
            }
            AtomicInteger resolverCalls = new AtomicInteger();

            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    fixture.request(kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, List.of(fixture.second), maliciousWire)
            ));
            assertEquals(0, resolverCalls.get());
        }
    }

    @Test
    void signedInnerTypAndAlgAreValidatedBeforeResolverOrVerification() {
        try (RealFixture fixture = new RealFixture()) {
            for (String field : List.of("typ", "alg")) {
                String maliciousWire = fixture.signedWireWithProtectedField(
                        field,
                        field.equals("typ") ? "wind+inner" : "ES256"
                );
                AtomicInteger resolverCalls = new AtomicInteger();
                RecordingEd25519 verifier = new RecordingEd25519(fixture.ed25519, true, null);

                assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver(verifier).receive(
                        fixture.request(kid -> {
                            resolverCalls.incrementAndGet();
                            return Optional.of(fixture.trustedSigningKey());
                        }, List.of(fixture.second), maliciousWire)
                ));
                assertEquals(0, resolverCalls.get());
                assertEquals(0, verifier.verifyCalls);
            }
        }
    }

    @Test
    void bindingFailurePrecedesTrustedKeyResolutionAndSignatureVerification() {
        try (RealFixture fixture = new RealFixture()) {
            String maliciousWire = fixture.authenticatedSignedWire(
                    new OuterBinding.Hashes(new byte[32], new byte[32])
            );
            AtomicInteger resolverCalls = new AtomicInteger();
            RecordingEd25519 verifier = new RecordingEd25519(fixture.ed25519, true, null);

            assertCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver(verifier).receive(
                    fixture.request(kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, List.of(fixture.second), maliciousWire)
            ));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void verifiesTheExactReceivedSigningSegmentsWithoutReserializingThem() {
        try (RealFixture fixture = new RealFixture()) {
            String wire = fixture.authenticatedNonCanonicalSignedWire();

            PublicX25519SignedReceiver.Result result = fixture.receiver().receive(
                    fixture.request(
                            kid -> Optional.of(fixture.trustedSigningKey()),
                            List.of(fixture.second),
                            wire
                    )
            );

            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID, result.authenticationStatus());
        }
    }

    @Test
    void successClearsAllReceiverOwnedCryptoSnapshots() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            RecordingEd25519 verifier = new RecordingEd25519(fixture.ed25519, true, null);
            PublicX25519SignedReceiver receiver = new PublicX25519SignedReceiver(
                    fixture.deriver, keyWrap, gcm, verifier
            );

            PublicX25519SignedReceiver.Result result = receiver.receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            );

            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertAllZero(
                    keyWrap.kek,
                    keyWrap.output,
                    gcm.key,
                    gcm.aad,
                    gcm.plaintext,
                    verifier.publicKey,
                    verifier.message,
                    verifier.signature
            );
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void signatureFalseAndProviderFailureClearAllReceiverOwnedCryptoSnapshots() {
        try (RealFixture fixture = new RealFixture()) {
            for (RuntimeException providerFailure : java.util.Arrays.asList(
                    null,
                    new CryptoOperationException("verification unavailable")
            )) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap);
                RecordingGcm gcm = new RecordingGcm(fixture.gcm);
                RecordingEd25519 verifier = new RecordingEd25519(
                        fixture.ed25519, false, providerFailure
                );
                PublicX25519SignedReceiver receiver = new PublicX25519SignedReceiver(
                        fixture.deriver, keyWrap, gcm, verifier
                );

                assertCode(
                        providerFailure == null ? ErrorCode.SIGNATURE_INVALID : ErrorCode.INTERNAL_ERROR,
                        () -> receiver.receive(fixture.request(
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(fixture.second)
                        ))
                );
                assertAllZero(
                        keyWrap.kek,
                        keyWrap.output,
                        gcm.key,
                        gcm.aad,
                        gcm.plaintext,
                        verifier.publicKey,
                        verifier.message,
                        verifier.signature
                );
                assertEquals(32, fixture.second.publicKey().length);
            }
        }
    }

    @Test
    void bindingAndUnknownSignerFailuresClearOuterSecretsAndDecryptedInner() {
        try (RealFixture fixture = new RealFixture()) {
            String wrongBindingWire = fixture.authenticatedSignedWire(
                    new OuterBinding.Hashes(new byte[32], new byte[32])
            );
            RecordingKeyWrap bindingKeyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm bindingGcm = new RecordingGcm(fixture.gcm);
            RecordingEd25519 bindingVerifier = new RecordingEd25519(fixture.ed25519, true, null);
            PublicX25519SignedReceiver bindingReceiver = new PublicX25519SignedReceiver(
                    fixture.deriver, bindingKeyWrap, bindingGcm, bindingVerifier
            );
            assertCode(ErrorCode.BINDING_FAILED, () -> bindingReceiver.receive(
                    fixture.request(
                            kid -> Optional.of(fixture.trustedSigningKey()),
                            List.of(fixture.second),
                            wrongBindingWire
                    )
            ));
            assertEquals(0, bindingVerifier.verifyCalls);
            assertAllZero(
                    bindingKeyWrap.kek,
                    bindingKeyWrap.output,
                    bindingGcm.key,
                    bindingGcm.aad,
                    bindingGcm.plaintext
            );

            RecordingKeyWrap unknownKeyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm unknownGcm = new RecordingGcm(fixture.gcm);
            PublicX25519SignedReceiver unknownReceiver = new PublicX25519SignedReceiver(
                    fixture.deriver, unknownKeyWrap, unknownGcm, fixture.ed25519
            );
            assertCode(ErrorCode.SIGNATURE_INVALID, () -> unknownReceiver.receive(
                    fixture.request(kid -> Optional.empty(), List.of(fixture.second))
            ));
            assertAllZero(
                    unknownKeyWrap.kek,
                    unknownKeyWrap.output,
                    unknownGcm.key,
                    unknownGcm.aad,
                    unknownGcm.plaintext
            );
        }
    }

    @Test
    void unwrapAndGcmFailuresClearEveryAvailableProviderArray() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap failingUnwrap = new RecordingKeyWrap(
                    fixture.keyWrap,
                    new CryptoOperationException("unwrap unavailable"),
                    null
            );
            PublicX25519SignedReceiver unwrapReceiver = new PublicX25519SignedReceiver(
                    fixture.deriver, failingUnwrap, fixture.gcm, fixture.ed25519
            );
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> unwrapReceiver.receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            ));
            assertAllZero(failingUnwrap.kek);

            byte[] malformedCek = new byte[31];
            java.util.Arrays.fill(malformedCek, (byte) 0x52);
            RecordingKeyWrap malformed = new RecordingKeyWrap(fixture.keyWrap, null, malformedCek);
            PublicX25519SignedReceiver malformedReceiver = new PublicX25519SignedReceiver(
                    fixture.deriver, malformed, fixture.gcm, fixture.ed25519
            );
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> malformedReceiver.receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
            ));
            assertAllZero(malformed.kek, malformed.output);

            for (boolean returnNull : List.of(false, true)) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap);
                RecordingGcm gcm = new RecordingGcm(
                        fixture.gcm,
                        returnNull ? null : new CryptoOperationException("GCM unavailable"),
                        returnNull
                );
                PublicX25519SignedReceiver receiver = new PublicX25519SignedReceiver(
                        fixture.deriver, keyWrap, gcm, fixture.ed25519
                );
                assertCode(ErrorCode.GCM_AUTH_FAILED, () -> receiver.receive(
                        fixture.request(kid -> Optional.of(fixture.trustedSigningKey()), List.of(fixture.second))
                ));
                assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad);
            }
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void constructorRequestAndResultEnforceSignedReceiverInvariants() {
        try (RealFixture fixture = new RealFixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519SignedReceiver(null, fixture.keyWrap, fixture.gcm, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519SignedReceiver(fixture.deriver, null, fixture.gcm, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519SignedReceiver(fixture.deriver, fixture.keyWrap, null, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519SignedReceiver(fixture.deriver, fixture.keyWrap, fixture.gcm, null));

            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Request(
                    fixture.wire, null, kid -> Optional.empty(), List.of()
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Request(
                    fixture.wire, kid -> Optional.empty(), null, List.of()
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Request(
                    fixture.wire, kid -> Optional.empty(), kid -> Optional.empty(), null
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Request(
                    fixture.wire,
                    kid -> Optional.empty(),
                    kid -> Optional.empty(),
                    java.util.Arrays.asList((X25519PrivateKeyHandle) null)
            ));
            assertThrows(IllegalArgumentException.class, () -> fixture.receiver().receive(null));

            PublicX25519SignedReceiver.Request nullWire = new PublicX25519SignedReceiver.Request(
                    null, kid -> Optional.empty(), kid -> Optional.empty(), List.of()
            );
            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(nullWire));

            ArrayList<X25519PrivateKeyHandle> callerHandles = new ArrayList<>();
            callerHandles.add(fixture.second);
            PublicX25519SignedReceiver.Request snapshot = fixture.request(
                    kid -> Optional.of(fixture.trustedSigningKey()), callerHandles
            );
            callerHandles.clear();
            assertEquals(1, snapshot.recipientPrivateKeys().size());
            assertArrayEquals(fixture.payload.data(), fixture.receiver().receive(snapshot).payload().data());

            ProtocolSenderIdentity identity = new ProtocolSenderIdentity(IDENTITY_ID, fixture.signingKid);
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Result(
                    null, MESSAGE_ID, TIMESTAMP, ProtocolAuthenticationStatus.SIGNED_VALID, identity
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Result(
                    fixture.payload, null, TIMESTAMP, ProtocolAuthenticationStatus.SIGNED_VALID, identity
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Result(
                    fixture.payload, MESSAGE_ID, TIMESTAMP, null, identity
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Result(
                    fixture.payload, MESSAGE_ID, TIMESTAMP, ProtocolAuthenticationStatus.UNSIGNED, identity
            ));
            assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedReceiver.Result(
                    fixture.payload, MESSAGE_ID, TIMESTAMP, ProtocolAuthenticationStatus.SIGNED_VALID, null
            ));
        }
    }

    private static void assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            int aggregate = 0;
            for (byte current : value) {
                aggregate |= current;
            }
            assertEquals(0, aggregate, "receiver-owned provider array was not cleared");
        }
    }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private final RuntimeException failure;
        private final byte[] forcedOutput;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(A256KeyWrapCrypto delegate) {
            this(delegate, null, null);
        }

        private RecordingKeyWrap(
                A256KeyWrapCrypto delegate,
                RuntimeException failure,
                byte[] forcedOutput
        ) {
            this.delegate = delegate;
            this.failure = failure;
            this.forcedOutput = forcedOutput;
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            return delegate.wrap(kek, keyToWrap);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            this.kek = kek;
            if (failure != null) {
                throw failure;
            }
            output = forcedOutput != null ? forcedOutput : delegate.unwrap(kek, wrappedKey);
            return output;
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final RuntimeException failure;
        private final boolean returnNull;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate) {
            this(delegate, null, false);
        }

        private RecordingGcm(A256GcmCrypto delegate, RuntimeException failure, boolean returnNull) {
            this.delegate = delegate;
            this.failure = failure;
            this.returnNull = returnNull;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
            this.key = key;
            this.aad = aad;
            if (failure != null) {
                throw failure;
            }
            if (returnNull) {
                return null;
            }
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }

    private static final class RecordingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final boolean verificationResult;
        private final RuntimeException failure;
        private int verifyCalls;
        private byte[] publicKey;
        private byte[] message;
        private byte[] signature;

        private RecordingEd25519(
                Ed25519Crypto delegate,
                boolean verificationResult,
                RuntimeException failure
        ) {
            this.delegate = delegate;
            this.verificationResult = verificationResult;
            this.failure = failure;
        }

        @Override
        public Ed25519PrivateKeyHandle generatePrivateKey() {
            return delegate.generatePrivateKey();
        }

        @Override
        public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            return delegate.importPrivateKey(privateKey);
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            return delegate.sign(privateKey, message);
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            verifyCalls++;
            this.publicKey = publicKey;
            this.message = message;
            this.signature = signature;
            if (failure != null) {
                throw failure;
            }
            return verificationResult;
        }
    }

    private static final class RealFixture implements AutoCloseable {
        private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        private final PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                x25519, new BouncyCastleHkdfCrypto()
        );
        private final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        private final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        private final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        private final X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
        private final Ed25519PrivateKeyHandle senderSigningKey = ed25519.generatePrivateKey();
        private final Ed25519PrivateKeyHandle unrelatedSigningKey = ed25519.generatePrivateKey();
        private final X25519PrivateKeyHandle first = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle second = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle unrelated = x25519.generatePrivateKey();
        private final ProtocolPayload payload = new ProtocolPayload(
                "application/octet-stream", new byte[]{0, 1, 2, (byte) 0xff}, 4
        );
        private final String signingKid;
        private final String wire;

        private RealFixture() {
            byte[] signingPublicKey = senderSigningKey.publicKey();
            try {
                signingKid = Ed25519KeyId.derive(signingPublicKey);
            } finally {
                java.util.Arrays.fill(signingPublicKey, (byte) 0);
            }
            PublicX25519SignedSender sender = new PublicX25519SignedSender(
                    new PublicX25519RecipientBuilder(deriver, keyWrap), gcm, ed25519
            );
            wire = sender.send(new PublicX25519SignedSender.Request(
                    payload,
                    MESSAGE_ID,
                    TIMESTAMP,
                    senderEncryptionKey,
                    senderSigningKey,
                    List.of(first.publicKey(), second.publicKey())
            )).wireJson();
        }

        private PublicX25519SignedReceiver receiver() {
            return new PublicX25519SignedReceiver(deriver, keyWrap, gcm, ed25519);
        }

        private PublicX25519SignedReceiver receiver(Ed25519Crypto verifier) {
            return new PublicX25519SignedReceiver(deriver, keyWrap, gcm, verifier);
        }

        private TrustedEd25519Key trustedSigningKey() {
            return new TrustedEd25519Key(IDENTITY_ID, signingKid, senderSigningKey.publicKey());
        }

        private PublicX25519SignedReceiver.Request request(
                com.windletter.protocol.signature.Ed25519VerificationKeyResolver signingResolver,
                List<X25519PrivateKeyHandle> recipientKeys
        ) {
            return request(signingResolver, recipientKeys, wire);
        }

        private PublicX25519SignedReceiver.Request request(
                com.windletter.protocol.signature.Ed25519VerificationKeyResolver signingResolver,
                List<X25519PrivateKeyHandle> recipientKeys,
                String candidateWire
        ) {
            return new PublicX25519SignedReceiver.Request(
                    candidateWire,
                    kid -> Optional.of(senderEncryptionKey.publicKey()),
                    signingResolver,
                    recipientKeys
            );
        }

        private OuterBinding.Hashes binding() {
            WindLetter letter = new JacksonOuterWireParser().parse(wire);
            return new OuterBinding().compute(letter.protectedHeader(), letter.recipients());
        }

        private String authenticatedSignedWire(OuterBinding.Hashes binding) {
            byte[] signature = null;
            byte[] inner = null;
            SignedInnerCodec codec = new SignedInnerCodec();
            try (SignedInnerCodec.Prepared prepared = codec.prepare(new SignedInnerCodec.Message(
                    MESSAGE_ID, TIMESTAMP, payload, binding, signingKid
            ))) {
                byte[] signingInput = prepared.signingInput();
                try {
                    signature = ed25519.sign(senderSigningKey, signingInput);
                } finally {
                    java.util.Arrays.fill(signingInput, (byte) 0);
                }
                inner = codec.assemble(prepared, signature);
                return authenticatedWire(inner);
            } finally {
                if (signature != null) {
                    java.util.Arrays.fill(signature, (byte) 0);
                }
                if (inner != null) {
                    java.util.Arrays.fill(inner, (byte) 0);
                }
            }
        }

        private String authenticatedNonCanonicalSignedWire() {
            OuterBinding.Hashes binding = binding();
            byte[] protectedHash = binding.protectedHash();
            byte[] recipientsHash = binding.recipientsHash();
            byte[] payloadData = payload.data();
            byte[] signingInput = null;
            byte[] signature = null;
            byte[] inner = null;
            try {
                String protectedJson = "{\"wind_id\":\"" + MESSAGE_ID
                        + "\", \"ts\":" + TIMESTAMP
                        + ", \"typ\":\"wind+jws\", \"kid\":\"" + signingKid
                        + "\", \"jwe_recipients_hash\":\"" + Base64Url.encode(recipientsHash)
                        + "\", \"jwe_protected_hash\":\"" + Base64Url.encode(protectedHash)
                        + "\", \"alg\":\"EdDSA\"}";
                String payloadJson = "{\"meta\":{\"original_size\":" + payload.originalSize()
                        + ",\"content_type\":\"application/octet-stream\"},"
                        + "\"body\":{\"data\":\"" + Base64Url.encode(payloadData) + "\"}}";
                String protectedValue = Base64Url.encode(protectedJson.getBytes(StandardCharsets.UTF_8));
                String payloadValue = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));
                signingInput = (protectedValue + "." + payloadValue).getBytes(StandardCharsets.US_ASCII);
                signature = ed25519.sign(senderSigningKey, signingInput);

                ObjectNode root = JSON.createObjectNode();
                root.put("signature", Base64Url.encode(signature));
                root.put("payload", payloadValue);
                root.put("protected", protectedValue);
                inner = JcsCanonicalizer.canonicalize(root);
                return authenticatedWire(inner);
            } finally {
                java.util.Arrays.fill(protectedHash, (byte) 0);
                java.util.Arrays.fill(recipientsHash, (byte) 0);
                java.util.Arrays.fill(payloadData, (byte) 0);
                if (signingInput != null) {
                    java.util.Arrays.fill(signingInput, (byte) 0);
                }
                if (signature != null) {
                    java.util.Arrays.fill(signature, (byte) 0);
                }
                if (inner != null) {
                    java.util.Arrays.fill(inner, (byte) 0);
                }
            }
        }

        private String authenticatedTamperedSignatureWire() {
            byte[] signature = null;
            byte[] validInner = null;
            byte[] tamperedSignature = null;
            try {
                SignedInnerCodec codec = new SignedInnerCodec();
                try (SignedInnerCodec.Prepared prepared = codec.prepare(new SignedInnerCodec.Message(
                        MESSAGE_ID, TIMESTAMP, payload, binding(), signingKid
                ))) {
                    byte[] signingInput = prepared.signingInput();
                    try {
                        signature = ed25519.sign(senderSigningKey, signingInput);
                    } finally {
                        java.util.Arrays.fill(signingInput, (byte) 0);
                    }
                    validInner = codec.assemble(prepared, signature);
                }

                ObjectNode root = (ObjectNode) JSON.readTree(validInner);
                tamperedSignature = Base64Url.decodeCanonical(
                        root.get("signature").textValue(), "test.inner.signature"
                );
                tamperedSignature[0] ^= 1;
                root.put("signature", Base64Url.encode(tamperedSignature));
                byte[] maliciousInner = JcsCanonicalizer.canonicalize(root);
                try {
                    return authenticatedWire(maliciousInner);
                } finally {
                    java.util.Arrays.fill(maliciousInner, (byte) 0);
                }
            } catch (Exception e) {
                throw new AssertionError("failed to build authenticated tampered signature", e);
            } finally {
                if (signature != null) {
                    java.util.Arrays.fill(signature, (byte) 0);
                }
                if (validInner != null) {
                    java.util.Arrays.fill(validInner, (byte) 0);
                }
                if (tamperedSignature != null) {
                    java.util.Arrays.fill(tamperedSignature, (byte) 0);
                }
            }
        }

        private String signedWireWithProtectedField(String field, String value) {
            byte[] validInner = null;
            byte[] protectedBytes = null;
            try {
                SignedInnerCodec codec = new SignedInnerCodec();
                byte[] signature;
                try (SignedInnerCodec.Prepared prepared = codec.prepare(new SignedInnerCodec.Message(
                        MESSAGE_ID, TIMESTAMP, payload, binding(), signingKid
                ))) {
                    byte[] signingInput = prepared.signingInput();
                    try {
                        signature = ed25519.sign(senderSigningKey, signingInput);
                    } finally {
                        java.util.Arrays.fill(signingInput, (byte) 0);
                    }
                    try {
                        validInner = codec.assemble(prepared, signature);
                    } finally {
                        java.util.Arrays.fill(signature, (byte) 0);
                    }
                }
                ObjectNode root = (ObjectNode) JSON.readTree(validInner);
                protectedBytes = Base64Url.decodeCanonical(
                        root.get("protected").textValue(), "test.inner.protected"
                );
                ObjectNode protectedNode = (ObjectNode) JSON.readTree(protectedBytes);
                protectedNode.put(field, value);
                root.put("protected", Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
                return authenticatedWire(JcsCanonicalizer.canonicalize(root));
            } catch (Exception e) {
                throw new AssertionError("failed to build authenticated malicious signed inner", e);
            } finally {
                if (validInner != null) {
                    java.util.Arrays.fill(validInner, (byte) 0);
                }
                if (protectedBytes != null) {
                    java.util.Arrays.fill(protectedBytes, (byte) 0);
                }
            }
        }

        private String authenticatedWire(byte[] innerBytes) {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            PublicRecipient recipient = (PublicRecipient) parsed.recipients().get(1);
            byte[] senderPublic = senderEncryptionKey.publicKey();
            byte[] kek = deriver.derive(second, senderPublic);
            byte[] cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            byte[] aad = new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad());
            try {
                AeadCiphertext encrypted = gcm.encrypt(cek, parsed.iv(), aad, innerBytes);
                WindLetter malicious = new WindLetter(
                        parsed.protectedHeader(),
                        parsed.protectedValue(),
                        parsed.aad(),
                        parsed.recipients(),
                        parsed.iv(),
                        encrypted.ciphertext(),
                        encrypted.tag()
                );
                return new JacksonOuterWireWriter().write(malicious);
            } finally {
                java.util.Arrays.fill(senderPublic, (byte) 0);
                java.util.Arrays.fill(kek, (byte) 0);
                java.util.Arrays.fill(cek, (byte) 0);
                java.util.Arrays.fill(aad, (byte) 0);
            }
        }

        @Override
        public void close() {
            unrelated.close();
            second.close();
            first.close();
            unrelatedSigningKey.close();
            senderSigningKey.close();
            senderEncryptionKey.close();
        }
    }
}
