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
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicHybridRecipientBuilder;
import com.windletter.protocol.recipient.PublicHybridRecipientKeys;
import com.windletter.protocol.routing.PublicHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicHybridSignedReceiverTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final String IDENTITY_ID = "trusted-sender-1";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void receivesRealSignedWireForSecondHybridRecipientAndReturnsTrustedIdentity() {
        try (RealFixture fixture = new RealFixture()) {
            PublicHybridSignedReceiver.Result result = fixture.receiver().receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
            );

            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                    result.authenticationStatus());
            assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
            assertEquals(fixture.signingKid, result.authenticatedSender().signingKid());
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void strictProfileAndAadGatesPrecedeRoutingAndBothResolvers() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger encryptionCalls = new AtomicInteger();
            AtomicInteger signingCalls = new AtomicInteger();
            SenderX25519PublicKeyResolver encryptionResolver = kid -> {
                encryptionCalls.incrementAndGet();
                return Optional.of(fixture.senderEncryptionKey.publicKey());
            };
            Ed25519VerificationKeyResolver signingResolver = kid -> {
                signingCalls.incrementAndGet();
                return Optional.of(fixture.trustedSigningKey());
            };

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    new PublicHybridSignedReceiver.Request(
                            "{", encryptionResolver, signingResolver,
                            List.of(fixture.unrelatedPair())
                    )
            ));
            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> fixture.receiver().receive(
                    new PublicHybridSignedReceiver.Request(
                            withProtectedCty(fixture.wire, "wind+inner"),
                            encryptionResolver,
                            signingResolver,
                            List.of(fixture.unrelatedPair())
                    )
            ));

            ObjectNode aadTampered = (ObjectNode) JSON.readTree(fixture.wire);
            aadTampered.put("aad", Base64Url.encode(new byte[]{1}));
            assertCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    new PublicHybridSignedReceiver.Request(
                            aadTampered.toString(), encryptionResolver, signingResolver,
                            List.of(fixture.unrelatedPair())
                    )
            ));

            assertEquals(0, encryptionCalls.get());
            assertEquals(0, signingCalls.get());
        }
    }

    @Test
    void unrelatedPairIsNotForMeBeforeResolversOrMlkemDecapsulation() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger encryptionCalls = new AtomicInteger();
            AtomicInteger signingCalls = new AtomicInteger();
            CountingMlKem768Crypto mlkem = new CountingMlKem768Crypto(fixture.mlkem, null);
            PublicHybridSignedReceiver receiver = new PublicHybridSignedReceiver(
                    new PublicHybridKekDeriver(
                            fixture.x25519, mlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm,
                    fixture.ed25519
            );

            assertCode(ErrorCode.NOT_FOR_ME, () -> receiver.receive(
                    new PublicHybridSignedReceiver.Request(
                            fixture.wire,
                            kid -> {
                                encryptionCalls.incrementAndGet();
                                return Optional.of(fixture.senderEncryptionKey.publicKey());
                            },
                            kid -> {
                                signingCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.unrelatedPair())
                    )
            ));
            assertEquals(0, encryptionCalls.get());
            assertEquals(0, signingCalls.get());
            assertEquals(0, mlkem.decapsulateCalls);
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void routerProtocolFailureIsPreservedBeforeResolvers() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger encryptionCalls = new AtomicInteger();
            AtomicInteger signingCalls = new AtomicInteger();
            ProtocolException failure = assertFailure(ErrorCode.INTERNAL_ERROR,
                    () -> fixture.receiver().receive(new PublicHybridSignedReceiver.Request(
                            fixture.wire,
                            kid -> {
                                encryptionCalls.incrementAndGet();
                                return Optional.empty();
                            },
                            kid -> {
                                signingCalls.incrementAndGet();
                                return Optional.empty();
                            },
                            List.of(new PublicHybridRecipientPrivateKeys(
                                    new ExplodingX25519Handle(), fixture.secondPq
                            ))
                    )));

            assertEquals("failed to inspect local hybrid key handles", failure.getMessage());
            assertInstanceOf(IllegalStateException.class, failure.getCause());
            assertEquals(0, encryptionCalls.get());
            assertEquals(0, signingCalls.get());
        }
    }

    @Test
    void bindingFailurePrecedesTrustedKeyResolutionAndVerification() {
        try (RealFixture fixture = new RealFixture()) {
            String maliciousWire = fixture.authenticatedSignedWire(
                    new OuterBinding.Hashes(new byte[32], new byte[32])
            );
            AtomicInteger resolverCalls = new AtomicInteger();
            RecordingEd25519 verifier = new RecordingEd25519(
                    fixture.ed25519, true, null
            );

            assertCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver(verifier).receive(
                    fixture.request(kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, maliciousWire)
            ));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void unknownSignerAndFalseVerificationAreSignatureInvalid() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver().receive(
                    fixture.request(kid -> Optional.empty())
            ));

            RecordingEd25519 rejecting = new RecordingEd25519(
                    fixture.ed25519, false, null
            );
            assertCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver(rejecting).receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
            ));
            assertEquals(1, rejecting.verifyCalls);
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void signingResolverAndTrustedRecordContractFailuresAreInternal() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(kid -> null)
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(kid -> {
                        throw new IllegalStateException("resolver unavailable");
                    })
            ));

            byte[] unrelatedPublic = fixture.unrelatedSigningKey.publicKey();
            try {
                String unrelatedKid = Ed25519KeyId.derive(unrelatedPublic);
                TrustedEd25519Key recordKidMismatch = new TrustedEd25519Key(
                        "other-identity", unrelatedKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                        fixture.request(kid -> Optional.of(recordKidMismatch))
                ));

                TrustedEd25519Key publicMismatch = new TrustedEd25519Key(
                        IDENTITY_ID, fixture.signingKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                        fixture.request(kid -> Optional.of(publicMismatch))
                ));
            } finally {
                Arrays.fill(unrelatedPublic, (byte) 0);
            }
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void verificationProviderFailureIsInternal() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingEd25519 failing = new RecordingEd25519(
                    fixture.ed25519,
                    true,
                    new CryptoOperationException("verification unavailable")
            );

            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver(failing).receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
            ));
            assertEquals(1, failing.verifyCalls);
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void verifiesExactReceivedSigningSegmentsWithoutReserializing() {
        try (RealFixture fixture = new RealFixture()) {
            PublicHybridSignedReceiver.Result result = fixture.receiver().receive(
                    fixture.request(
                            kid -> Optional.of(fixture.trustedSigningKey()),
                            fixture.authenticatedNonCanonicalSignedWire()
                    )
            );

            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                    result.authenticationStatus());
        }
    }

    @Test
    void lowOrderX25519MlkemAndUnwrapFailuresShareGenericRecoveryError() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger signingCalls = new AtomicInteger();
            byte[] lowOrder = new byte[32];
            assertGenericKeyRecovery(() -> fixture.receiver().receive(
                    new PublicHybridSignedReceiver.Request(
                            withSenderKid(fixture.wire, X25519KeyId.derive(lowOrder)),
                            kid -> Optional.of(lowOrder),
                            kid -> {
                                signingCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.secondPair())
                    )
            ));

            CountingMlKem768Crypto failingMlkem = new CountingMlKem768Crypto(
                    fixture.mlkem,
                    new CryptoOperationException("decapsulation failed")
            );
            PublicHybridSignedReceiver mlkemReceiver = new PublicHybridSignedReceiver(
                    new PublicHybridKekDeriver(
                            fixture.x25519, failingMlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm,
                    fixture.ed25519
            );
            assertGenericKeyRecovery(() -> mlkemReceiver.receive(
                    fixture.request(kid -> {
                        signingCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    })
            ));
            assertEquals(1, failingMlkem.decapsulateCalls);

            RecordingKeyWrap failingUnwrap = new RecordingKeyWrap(
                    fixture.keyWrap,
                    new CryptoOperationException("unwrap failed")
            );
            PublicHybridSignedReceiver unwrapReceiver = new PublicHybridSignedReceiver(
                    fixture.deriver, failingUnwrap, fixture.gcm, fixture.ed25519
            );
            assertGenericKeyRecovery(() -> unwrapReceiver.receive(
                    fixture.request(kid -> {
                        signingCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    })
            ));
            assertAllZero(failingUnwrap.kek);
            assertEquals(0, signingCalls.get());
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void successAndSignatureFailuresClearReceiverOwnedCryptoArrays() {
        try (RealFixture fixture = new RealFixture()) {
            for (RuntimeException providerFailure : Arrays.asList(
                    null,
                    new CryptoOperationException("verification unavailable")
            )) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap, null);
                RecordingGcm gcm = new RecordingGcm(fixture.gcm);
                RecordingEd25519 verifier = new RecordingEd25519(
                        fixture.ed25519, providerFailure == null, providerFailure
                );
                PublicHybridSignedReceiver receiver = new PublicHybridSignedReceiver(
                        fixture.deriver, keyWrap, gcm, verifier
                );

                if (providerFailure == null) {
                    PublicHybridSignedReceiver.Result result = receiver.receive(
                            fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
                    );
                    assertArrayEquals(fixture.payload.data(), result.payload().data());
                } else {
                    assertCode(ErrorCode.INTERNAL_ERROR, () -> receiver.receive(
                            fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
                    ));
                }
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
                assertBorrowedHandlesOpen(fixture);
            }

            RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap, null);
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            RecordingEd25519 rejecting = new RecordingEd25519(
                    fixture.ed25519, false, null
            );
            PublicHybridSignedReceiver receiver = new PublicHybridSignedReceiver(
                    fixture.deriver, keyWrap, gcm, rejecting
            );
            assertCode(ErrorCode.SIGNATURE_INVALID, () -> receiver.receive(
                    fixture.request(kid -> Optional.of(fixture.trustedSigningKey()))
            ));
            assertAllZero(
                    keyWrap.kek,
                    keyWrap.output,
                    gcm.key,
                    gcm.aad,
                    gcm.plaintext,
                    rejecting.publicKey,
                    rejecting.message,
                    rejecting.signature
            );
            assertBorrowedHandlesOpen(fixture);
        }
    }

    @Test
    void requestSnapshotsPairsAndResultEnforcesSignedIdentity() {
        try (RealFixture fixture = new RealFixture()) {
            ArrayList<PublicHybridRecipientPrivateKeys> callerPairs = new ArrayList<>();
            callerPairs.add(fixture.secondPair());
            PublicHybridSignedReceiver.Request snapshot = new PublicHybridSignedReceiver.Request(
                    fixture.wire,
                    kid -> Optional.of(fixture.senderEncryptionKey.publicKey()),
                    kid -> Optional.of(fixture.trustedSigningKey()),
                    callerPairs
            );
            callerPairs.clear();
            assertEquals(1, snapshot.recipientPrivateKeys().size());
            assertArrayEquals(fixture.payload.data(),
                    fixture.receiver().receive(snapshot).payload().data());

            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver(
                            null, fixture.keyWrap, fixture.gcm, fixture.ed25519
                    ));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver.Request(
                            fixture.wire, null, kid -> Optional.empty(), List.of()
                    ));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver.Request(
                            fixture.wire, kid -> Optional.empty(), null, List.of()
                    ));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver.Request(
                            fixture.wire,
                            kid -> Optional.empty(),
                            kid -> Optional.empty(),
                            Arrays.asList((PublicHybridRecipientPrivateKeys) null)
                    ));

            ProtocolSenderIdentity identity = new ProtocolSenderIdentity(
                    IDENTITY_ID, fixture.signingKid
            );
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver.Result(
                            fixture.payload,
                            MESSAGE_ID,
                            TIMESTAMP,
                            ProtocolAuthenticationStatus.UNSIGNED,
                            identity
                    ));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridSignedReceiver.Result(
                            fixture.payload,
                            MESSAGE_ID,
                            TIMESTAMP,
                            ProtocolAuthenticationStatus.SIGNED_VALID,
                            null
                    ));
        }
    }

    private static String withProtectedCty(String wire, String cty) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            ObjectNode protectedNode = decodeProtected(root);
            protectedNode.put("cty", cty);
            root.put("protected",
                    Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to replace protected cty", e);
        }
    }

    private static String withSenderKid(String wire, String x25519Kid) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            ObjectNode protectedNode = decodeProtected(root);
            ((ObjectNode) protectedNode.get("kid")).put("x25519", x25519Kid);
            root.put("protected",
                    Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to replace sender kid", e);
        }
    }

    private static ObjectNode decodeProtected(ObjectNode root) throws Exception {
        byte[] value = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        try {
            return (ObjectNode) JSON.readTree(value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static ProtocolException assertGenericKeyRecovery(Runnable operation) {
        ProtocolException failure = assertFailure(ErrorCode.KEY_UNWRAP_FAILED, operation);
        assertEquals("hybrid recipient key recovery failed", failure.getMessage());
        assertNull(failure.getCause());
        return failure;
    }

    private static void assertCode(ErrorCode expected, Runnable operation) {
        assertFailure(expected, operation);
    }

    private static ProtocolException assertFailure(
            ErrorCode expected,
            Runnable operation
    ) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        return failure;
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

    private static void assertBorrowedHandlesOpen(RealFixture fixture) {
        assertEquals(32, fixture.senderEncryptionKey.publicKey().length);
        assertEquals(32, fixture.senderSigningKey.publicKey().length);
        assertEquals(32, fixture.secondX.publicKey().length);
        assertEquals(1184, fixture.secondPq.publicKey().length);
    }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private final RuntimeException failure;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(A256KeyWrapCrypto delegate, RuntimeException failure) {
            this.delegate = delegate;
            this.failure = failure;
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
            output = delegate.unwrap(kek, wrappedKey);
            return output;
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key,
                byte[] iv,
                byte[] aad,
                byte[] ciphertext,
                byte[] tag
        ) {
            this.key = key;
            this.aad = aad;
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }

    private static final class RecordingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final boolean result;
        private final RuntimeException failure;
        private int verifyCalls;
        private byte[] publicKey;
        private byte[] message;
        private byte[] signature;

        private RecordingEd25519(
                Ed25519Crypto delegate,
                boolean result,
                RuntimeException failure
        ) {
            this.delegate = delegate;
            this.result = result;
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
            return result;
        }
    }

    private static final class CountingMlKem768Crypto implements MLKem768Crypto {
        private final MLKem768Crypto delegate;
        private final RuntimeException failure;
        private int decapsulateCalls;

        private CountingMlKem768Crypto(
                MLKem768Crypto delegate,
                RuntimeException failure
        ) {
            this.delegate = delegate;
            this.failure = failure;
        }

        @Override
        public MLKem768PrivateKeyHandle generatePrivateKey() {
            return delegate.generatePrivateKey();
        }

        @Override
        public MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            return delegate.importPrivateKey(privateKey);
        }

        @Override
        public MLKem768Encapsulation encapsulate(byte[] publicKey) {
            return delegate.encapsulate(publicKey);
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            decapsulateCalls++;
            if (failure != null) {
                throw failure;
            }
            return delegate.decapsulate(privateKey, ciphertext);
        }
    }

    private static final class ExplodingX25519Handle implements X25519PrivateKeyHandle {
        @Override
        public byte[] publicKey() {
            throw new IllegalStateException("local handle unavailable");
        }

        @Override
        public void close() {
        }
    }

    private static final class RealFixture implements AutoCloseable {
        private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        private final BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        private final BouncyCastleA256KeyWrapCrypto keyWrap =
                new BouncyCastleA256KeyWrapCrypto();
        private final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        private final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        private final PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        private final X25519PrivateKeyHandle senderEncryptionKey =
                x25519.generatePrivateKey();
        private final Ed25519PrivateKeyHandle senderSigningKey =
                ed25519.generatePrivateKey();
        private final Ed25519PrivateKeyHandle unrelatedSigningKey =
                ed25519.generatePrivateKey();
        private final X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
        private final X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey();
        private final X25519PrivateKeyHandle unrelatedX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle unrelatedPq = mlkem.generatePrivateKey();
        private final ProtocolPayload payload = new ProtocolPayload(
                "application/octet-stream",
                new byte[]{0, (byte) 0xff, (byte) 0xc3, 0x28},
                4
        );
        private final String signingKid;
        private final String wire;

        private RealFixture() {
            byte[] signingPublic = senderSigningKey.publicKey();
            try {
                signingKid = Ed25519KeyId.derive(signingPublic);
            } finally {
                Arrays.fill(signingPublic, (byte) 0);
            }
            PublicHybridSignedSender sender = new PublicHybridSignedSender(
                    new PublicHybridRecipientBuilder(deriver, keyWrap),
                    gcm,
                    ed25519
            );
            wire = sender.send(new PublicHybridSignedSender.Request(
                    payload,
                    MESSAGE_ID,
                    TIMESTAMP,
                    senderEncryptionKey,
                    senderSigningKey,
                    List.of(keys(firstX, firstPq), keys(secondX, secondPq))
            )).wireJson();
        }

        private PublicHybridSignedReceiver receiver() {
            return receiver(ed25519);
        }

        private PublicHybridSignedReceiver receiver(Ed25519Crypto verifier) {
            return new PublicHybridSignedReceiver(deriver, keyWrap, gcm, verifier);
        }

        private PublicHybridRecipientPrivateKeys secondPair() {
            return new PublicHybridRecipientPrivateKeys(secondX, secondPq);
        }

        private PublicHybridRecipientPrivateKeys unrelatedPair() {
            return new PublicHybridRecipientPrivateKeys(unrelatedX, unrelatedPq);
        }

        private TrustedEd25519Key trustedSigningKey() {
            return new TrustedEd25519Key(
                    IDENTITY_ID, signingKid, senderSigningKey.publicKey()
            );
        }

        private PublicHybridSignedReceiver.Request request(
                Ed25519VerificationKeyResolver signingResolver
        ) {
            return request(signingResolver, wire);
        }

        private PublicHybridSignedReceiver.Request request(
                Ed25519VerificationKeyResolver signingResolver,
                String candidateWire
        ) {
            return new PublicHybridSignedReceiver.Request(
                    candidateWire,
                    kid -> Optional.of(senderEncryptionKey.publicKey()),
                    signingResolver,
                    List.of(secondPair())
            );
        }

        private OuterBinding.Hashes binding() {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            return new OuterBinding().compute(
                    parsed.protectedHeader(), parsed.recipients()
            );
        }

        private String authenticatedSignedWire(OuterBinding.Hashes binding) {
            byte[] signature = null;
            byte[] inner = null;
            SignedInnerCodec codec = new SignedInnerCodec();
            try (SignedInnerCodec.Prepared prepared = codec.prepare(
                    new SignedInnerCodec.Message(
                            MESSAGE_ID, TIMESTAMP, payload, binding, signingKid
                    )
            )) {
                byte[] signingInput = prepared.signingInput();
                try {
                    signature = ed25519.sign(senderSigningKey, signingInput);
                } finally {
                    Arrays.fill(signingInput, (byte) 0);
                }
                inner = codec.assemble(prepared, signature);
                return authenticatedWire(inner);
            } finally {
                if (signature != null) {
                    Arrays.fill(signature, (byte) 0);
                }
                if (inner != null) {
                    Arrays.fill(inner, (byte) 0);
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
                        + "\", \"jwe_recipients_hash\":\""
                        + Base64Url.encode(recipientsHash)
                        + "\", \"jwe_protected_hash\":\""
                        + Base64Url.encode(protectedHash)
                        + "\", \"alg\":\"EdDSA\"}";
                String payloadJson = "{\"meta\":{\"original_size\":"
                        + payload.originalSize()
                        + ",\"content_type\":\"application/octet-stream\"},"
                        + "\"body\":{\"data\":\""
                        + Base64Url.encode(payloadData) + "\"}}";
                String protectedValue = Base64Url.encode(
                        protectedJson.getBytes(StandardCharsets.UTF_8)
                );
                String payloadValue = Base64Url.encode(
                        payloadJson.getBytes(StandardCharsets.UTF_8)
                );
                signingInput = (protectedValue + "." + payloadValue)
                        .getBytes(StandardCharsets.US_ASCII);
                signature = ed25519.sign(senderSigningKey, signingInput);

                ObjectNode root = JSON.createObjectNode();
                root.put("signature", Base64Url.encode(signature));
                root.put("payload", payloadValue);
                root.put("protected", protectedValue);
                inner = JcsCanonicalizer.canonicalize(root);
                return authenticatedWire(inner);
            } finally {
                Arrays.fill(protectedHash, (byte) 0);
                Arrays.fill(recipientsHash, (byte) 0);
                Arrays.fill(payloadData, (byte) 0);
                if (signingInput != null) {
                    Arrays.fill(signingInput, (byte) 0);
                }
                if (signature != null) {
                    Arrays.fill(signature, (byte) 0);
                }
                if (inner != null) {
                    Arrays.fill(inner, (byte) 0);
                }
            }
        }

        private String authenticatedWire(byte[] innerBytes) {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            PublicRecipient recipient = (PublicRecipient) parsed.recipients().get(1);
            byte[] senderPublic = senderEncryptionKey.publicKey();
            byte[] ek = recipient.ek();
            byte[] kek = deriver.deriveForReceiver(
                    secondX, senderPublic, secondPq, ek
            );
            byte[] cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            byte[] aad = new OuterAad().gcmInput(
                    parsed.protectedValue(), parsed.aad()
            );
            try {
                AeadCiphertext encrypted = gcm.encrypt(
                        cek, parsed.iv(), aad, innerBytes
                );
                return new JacksonOuterWireWriter().write(new WindLetter(
                        parsed.protectedHeader(),
                        parsed.protectedValue(),
                        parsed.aad(),
                        parsed.recipients(),
                        parsed.iv(),
                        encrypted.ciphertext(),
                        encrypted.tag()
                ));
            } finally {
                Arrays.fill(senderPublic, (byte) 0);
                Arrays.fill(ek, (byte) 0);
                Arrays.fill(kek, (byte) 0);
                Arrays.fill(cek, (byte) 0);
                Arrays.fill(aad, (byte) 0);
            }
        }

        @Override
        public void close() {
            unrelatedPq.close();
            unrelatedX.close();
            secondPq.close();
            secondX.close();
            firstPq.close();
            firstX.close();
            unrelatedSigningKey.close();
            senderSigningKey.close();
            senderEncryptionKey.close();
        }
    }

    private static PublicHybridRecipientKeys keys(
            X25519PrivateKeyHandle x25519,
            MLKem768PrivateKeyHandle mlkem768
    ) {
        return new PublicHybridRecipientKeys(
                x25519.publicKey(), mlkem768.publicKey()
        );
    }
}
