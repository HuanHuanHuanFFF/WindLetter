package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientKeys;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridSignedSenderTest {

    @Test
    void signsExactPreparedSegmentsAndEncryptsTheFinalHybridBucket() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            RecordingEd25519 signer = new RecordingEd25519(
                    fixture.ed25519, SignMode.DELEGATE
            );
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            TrackingRandom random = new TrackingRandom();
            ObfuscationHybridSignedSender sender =
                    new ObfuscationHybridSignedSender(
                            fixture.builder(), gcm, signer, random
                    );

            ObfuscationHybridSignedSender.Result result = sender.send(
                    new ObfuscationHybridSignedSender.Request(
                            fixture.binaryPayload(),
                            ProtocolFlowTestFixtures.MESSAGE_ID,
                            ProtocolFlowTestFixtures.TIMESTAMP,
                            fixture.senderSigning,
                            fixture.recipients().stream()
                                    .map(ObfuscationHybridFlowTestFixtures.HybridPair::publicKeys)
                                    .toList()
                    )
            );
            WindLetter parsed = new com.windletter.protocol.parser.JacksonOuterWireParser()
                    .parse(result.wireJson());

            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+jws", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("obfuscation", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519ML-KEM-768", parsed.protectedHeader().keyAlg());
            Epk epk = assertInstanceOf(
                    Epk.class, parsed.protectedHeader().senderInfo()
            );
            assertEquals(32, epk.x().length);
            assertEquals(8, parsed.recipients().size());
            parsed.recipients().forEach(entry -> {
                ObfuscationRecipient recipient = assertInstanceOf(
                        ObfuscationRecipient.class, entry
                );
                assertEquals(16, recipient.rid().length);
                assertEquals(40, recipient.encryptedKey().length);
                assertEquals(1088, recipient.ek().length);
            });
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
            assertArrayEquals(
                    new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad()),
                    gcm.aadSnapshot
            );

            byte[] signingPublic = fixture.senderSigning.publicKey();
            try (SignedInnerCodec.Decoded decoded =
                         new SignedInnerCodec().decode(gcm.plaintextSnapshot)) {
                assertEquals(
                        Ed25519KeyId.derive(signingPublic),
                        decoded.message().signingKid()
                );
                assertArrayEquals(signer.messageSnapshot, decoded.signingInput());
                assertArrayEquals(signer.signatureSnapshot, decoded.signature());
                OuterBinding.Hashes binding = new OuterBinding().compute(
                        parsed.protectedHeader(), parsed.recipients()
                );
                assertArrayEquals(
                        binding.protectedHash(),
                        decoded.message().binding().protectedHash()
                );
                assertArrayEquals(
                        binding.recipientsHash(),
                        decoded.message().binding().recipientsHash()
                );
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(signingPublic);
            }

            assertEquals(1, signer.signCalls);
            assertEquals(2, random.references.size());
            assertEquals(4, gcm.rawReferences().size());
            assertTrue(signer.rawReferences().stream().allMatch(
                    ObfuscationHybridSignedSenderTest::allZero
            ));
            assertTrue(random.references.stream().allMatch(
                    ObfuscationHybridSignedSenderTest::allZero
            ));
            assertTrue(gcm.rawReferences().stream().allMatch(
                    ObfuscationHybridSignedSenderTest::allZero
            ));
            byte[] borrowedHandleProbe = fixture.senderSigning.publicKey();
            try {
                assertEquals(32, borrowedHandleProbe.length);
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(borrowedHandleProbe);
            }
            ObfuscationHybridFlowTestFixtures.clear(signer.messageSnapshot);
            ObfuscationHybridFlowTestFixtures.clear(signer.signatureSnapshot);
            ObfuscationHybridFlowTestFixtures.clear(gcm.aadSnapshot);
            ObfuscationHybridFlowTestFixtures.clear(gcm.plaintextSnapshot);
        }
    }

    @Test
    void requestUsesCompletePairDuplicatesAndBorrowsTheSigningHandle() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            ObfuscationHybridRecipientKeys first = fixture.first.publicKeys();
            ObfuscationHybridRecipientKeys middle = fixture.middle.publicKeys();
            byte[] firstX = first.x25519PublicKey();
            byte[] firstPq = first.mlkem768PublicKey();
            byte[] middleX = middle.x25519PublicKey();
            byte[] middlePq = middle.mlkem768PublicKey();
            try {
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridSignedSender.Request(
                                fixture.binaryPayload(),
                                ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP,
                                fixture.senderSigning,
                                List.of(first, new ObfuscationHybridRecipientKeys(
                                        firstX, firstPq
                                ))
                        ));
                ObfuscationHybridSignedSender.Request allowed =
                        new ObfuscationHybridSignedSender.Request(
                                fixture.binaryPayload(),
                                ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP,
                                fixture.senderSigning,
                                List.of(
                                        new ObfuscationHybridRecipientKeys(firstX, firstPq),
                                        new ObfuscationHybridRecipientKeys(firstX, middlePq),
                                        new ObfuscationHybridRecipientKeys(middleX, firstPq)
                                )
                        );
                assertEquals(3, allowed.recipients().size());
                assertSame(
                        fixture.senderSigning,
                        allowed.senderSigningPrivateKey()
                );
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(firstX);
                ObfuscationHybridFlowTestFixtures.clear(firstPq);
                ObfuscationHybridFlowTestFixtures.clear(middleX);
                ObfuscationHybridFlowTestFixtures.clear(middlePq);
            }
        }
    }

    @Test
    void rejectsNullOrWrongLengthSignaturesBeforeGcm() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            for (SignMode mode : List.of(SignMode.NULL, SignMode.WRONG_LENGTH)) {
                RecordingEd25519 signer = new RecordingEd25519(fixture.ed25519, mode);
                RecordingGcm gcm = new RecordingGcm(fixture.gcm);
                TrackingRandom random = new TrackingRandom();
                assertThrows(IllegalStateException.class, () ->
                        new ObfuscationHybridSignedSender(
                                fixture.builder(), gcm, signer, random
                        ).send(new ObfuscationHybridSignedSender.Request(
                                fixture.binaryPayload(),
                                ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP,
                                fixture.senderSigning,
                                List.of(fixture.first.publicKeys())
                        ))
                );
                assertEquals(0, gcm.encryptCalls);
                assertEquals(2, random.references.size());
                assertTrue(random.references.stream().allMatch(
                        ObfuscationHybridSignedSenderTest::allZero
                ));
                assertTrue(signer.rawReferences().stream().allMatch(
                        ObfuscationHybridSignedSenderTest::allZero
                ));
            }
        }
    }

    private static boolean allZero(byte[] value) {
        if (value == null) return false;
        for (byte current : value) {
            if (current != 0) return false;
        }
        return true;
    }

    private enum SignMode { DELEGATE, NULL, WRONG_LENGTH }

    private static final class RecordingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final SignMode mode;
        private int signCalls;
        private byte[] message;
        private byte[] signature;
        private byte[] messageSnapshot;
        private byte[] signatureSnapshot;

        private RecordingEd25519(Ed25519Crypto delegate, SignMode mode) {
            this.delegate = delegate;
            this.mode = mode;
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
            signCalls++;
            this.message = message;
            messageSnapshot = message.clone();
            signature = switch (mode) {
                case NULL -> null;
                case WRONG_LENGTH -> new byte[63];
                case DELEGATE -> delegate.sign(privateKey, message);
            };
            if (signature != null) signatureSnapshot = signature.clone();
            return signature;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return delegate.verify(publicKey, message, signature);
        }

        private List<byte[]> rawReferences() {
            ArrayList<byte[]> values = new ArrayList<>();
            if (message != null) values.add(message);
            if (signature != null) values.add(signature);
            return values;
        }
    }

    private static final class TrackingRandom extends SecureRandom {
        private final SecureRandom delegate = new SecureRandom();
        private final ArrayList<byte[]> references = new ArrayList<>();

        @Override
        public void nextBytes(byte[] bytes) {
            delegate.nextBytes(bytes);
            references.add(bytes);
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private int encryptCalls;
        private byte[] key;
        private byte[] iv;
        private byte[] aad;
        private byte[] plaintext;
        private byte[] aadSnapshot;
        private byte[] plaintextSnapshot;

        private RecordingGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] plaintext
        ) {
            encryptCalls++;
            this.key = key;
            this.iv = iv;
            this.aad = aad;
            this.plaintext = plaintext;
            aadSnapshot = aad.clone();
            plaintextSnapshot = plaintext.clone();
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag
        ) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
        }

        private List<byte[]> rawReferences() {
            return List.of(key, iv, aad, plaintext);
        }
    }
}
