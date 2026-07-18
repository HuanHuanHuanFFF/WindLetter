package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicHybridRecipientBuilder;
import com.windletter.protocol.recipient.PublicHybridRecipientKeys;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridSignedSenderTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final byte[] PAYLOAD_BYTES = {0, (byte) 0xff, (byte) 0xc3, 0x28};

    @Test
    void sendsStrictTwoRecipientSignedWireThatBothRecipientsRecoverAndVerify() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                new PublicHybridRecipientBuilder(deriver, keyWrap), gcm, ed25519
        );

        try (X25519PrivateKeyHandle senderX = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigning = ed25519.generatePrivateKey();
             X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
             X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey()) {
            byte[] senderXPublic = senderX.publicKey();
            byte[] signingPublic = senderSigning.publicKey();
            byte[] firstXPublic = firstX.publicKey();
            byte[] firstPqPublic = firstPq.publicKey();
            byte[] secondXPublic = secondX.publicKey();
            byte[] secondPqPublic = secondPq.publicKey();
            PublicHybridSignedSender.Result result = sender.send(
                    new PublicHybridSignedSender.Request(
                            payload(), MESSAGE_ID, TIMESTAMP, senderX, senderSigning,
                            List.of(
                                    new PublicHybridRecipientKeys(firstXPublic, firstPqPublic),
                                    new PublicHybridRecipientKeys(secondXPublic, secondPqPublic)
                            )
                    )
            );
            WindLetter letter = new JacksonOuterWireParser().parse(result.wireJson());

            assertEquals("wind+jwe", letter.protectedHeader().typ());
            assertEquals("wind+jws", letter.protectedHeader().cty());
            assertEquals("1.0", letter.protectedHeader().ver());
            assertEquals("public", letter.protectedHeader().windMode());
            assertEquals("A256GCM", letter.protectedHeader().enc());
            assertEquals("X25519ML-KEM-768", letter.protectedHeader().keyAlg());
            SenderKid senderKid = assertInstanceOf(
                    SenderKid.class, letter.protectedHeader().senderInfo()
            );
            assertEquals(X25519KeyId.derive(senderXPublic), senderKid.x25519());
            assertEquals(
                    Base64Url.encode(JcsCanonicalizer.canonicalize(
                            OuterJsonMapper.toProtectedJson(letter.protectedHeader())
                    )),
                    letter.protectedValue()
            );
            assertEquals(new OuterAad().compute(letter.recipients()), letter.aad());
            assertEquals(2, letter.recipients().size());

            PublicRecipient first = assertInstanceOf(
                    PublicRecipient.class, letter.recipients().get(0)
            );
            PublicRecipient second = assertInstanceOf(
                    PublicRecipient.class, letter.recipients().get(1)
            );
            assertRecipient(first, firstXPublic, firstPqPublic);
            assertRecipient(second, secondXPublic, secondPqPublic);
            assertFalse(Arrays.equals(first.ek(), second.ek()));

            assertRecoveredAndVerified(
                    firstX, firstPq, first, senderXPublic, signingPublic,
                    letter, deriver, keyWrap, gcm, ed25519
            );
            assertRecoveredAndVerified(
                    secondX, secondPq, second, senderXPublic, signingPublic,
                    letter, deriver, keyWrap, gcm, ed25519
            );
            assertArrayEquals(letter.iv(), result.message().iv());
            assertArrayEquals(letter.ciphertext(), result.message().ciphertext());
            assertArrayEquals(letter.tag(), result.message().tag());
            assertEquals(32, senderX.publicKey().length);
            assertEquals(32, senderSigning.publicKey().length);

            clear(senderXPublic, signingPublic, firstXPublic, firstPqPublic,
                    secondXPublic, secondPqPublic);
        }
    }

    @Test
    void signsTheExactPreparedSegmentsAndClearsProviderInputAndSignature() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        RecordingEd25519 ed25519 = new RecordingEd25519(realEd25519);
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                new PublicHybridRecipientBuilder(deriver, keyWrap), gcm, ed25519
        );

        try (X25519PrivateKeyHandle senderX = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigning = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            String wire = sender.send(request(
                    senderX, senderSigning, keys(recipientX, recipientPq)
            )).wireJson();
            WindLetter letter = new JacksonOuterWireParser().parse(wire);
            PublicRecipient recipient = (PublicRecipient) letter.recipients().get(0);
            byte[] senderPublic = senderX.publicKey();
            byte[] signingPublic = senderSigning.publicKey();
            byte[] ek = recipient.ek();
            byte[] kek = deriver.deriveForReceiver(
                    recipientX, senderPublic, recipientPq, ek
            );
            byte[] cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            byte[] aad = new OuterAad().gcmInput(letter.protectedValue(), letter.aad());
            byte[] inner = gcm.decrypt(
                    cek, letter.iv(), aad, letter.ciphertext(), letter.tag()
            );
            try (SignedInnerCodec.Decoded decoded = new SignedInnerCodec().decode(inner)) {
                byte[] exactInput = decoded.signingInput();
                byte[] exactSignature = decoded.signature();
                try {
                    assertEquals(1, ed25519.signCalls);
                    assertArrayEquals(exactInput, ed25519.signingInputSnapshot);
                    assertArrayEquals(exactSignature, ed25519.signatureSnapshot);
                    assertEquals(
                            Ed25519KeyId.derive(signingPublic),
                            decoded.message().signingKid()
                    );
                    assertTrue(realEd25519.verify(
                            signingPublic, exactInput, exactSignature
                    ));
                } finally {
                    clear(exactInput, exactSignature);
                }
            } finally {
                assertAllZero(ed25519.references);
                clear(senderPublic, signingPublic, ek, kek, cek, aad, inner);
            }
        }
    }

    @Test
    void rejectsNullShortAndLongProviderSignaturesAndClearsProducedReferences() {
        assertBadSignatureContract(null);
        assertBadSignatureContract(new byte[63]);
        assertBadSignatureContract(new byte[65]);
    }

    @Test
    void signingFailureClearsGeneratedSecretsAndLeavesBorrowedHandlesOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        ThrowingEd25519 ed25519 = new ThrowingEd25519();
        SequenceSecureRandom random = new SequenceSecureRandom();
        RecordingGcm gcm = new RecordingGcm(new BouncyCastleA256GcmCrypto());
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                realRecipientBuilder(x25519, mlkem), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderX = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigning = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class, () -> sender.send(request(
                    senderX, senderSigning, keys(recipientX, recipientPq)
            )));

            assertEquals(1, ed25519.signCalls);
            assertEquals(0, gcm.encryptCalls);
            assertAllZero(ed25519.references);
            assertAllZero(random.references);
            assertEquals(32, senderX.publicKey().length);
            assertEquals(32, senderSigning.publicKey().length);
            assertEquals(32, recipientX.publicKey().length);
            assertEquals(1184, recipientPq.publicKey().length);
        }
    }

    @Test
    void gcmFailureClearsPublicSnapshotsAndAllOwnedCryptoArraysWithoutClosingHandles() {
        TrackingX25519Crypto x25519 = new TrackingX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        TrackingEd25519Crypto ed25519 = new TrackingEd25519Crypto();
        FailingGcm gcm = new FailingGcm();
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                new PublicHybridRecipientBuilder(
                        new PublicHybridKekDeriver(
                                x25519, mlkem, new BouncyCastleHkdfCrypto()
                        ),
                        new BouncyCastleA256KeyWrapCrypto()
                ),
                gcm,
                ed25519,
                random
        );
        try (TrackingX25519Handle senderX = x25519.generatePrivateKey();
             TrackingEd25519Handle senderSigning = ed25519.generatePrivateKey();
             TrackingX25519Handle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            PublicHybridRecipientKeys recipient = keys(recipientX, recipientPq);
            recipientX.clearCapturedPublicKeys();

            assertThrows(CryptoOperationException.class, () -> sender.send(request(
                    senderX, senderSigning, recipient
            )));

            assertEquals(1, ed25519.signCalls);
            assertEquals(1, gcm.encryptCalls);
            assertAllZero(senderX.capturedPublicKeys);
            assertAllZero(senderSigning.capturedPublicKeys);
            assertAllZero(ed25519.references);
            assertAllZero(gcm.references);
            assertAllZero(random.references);
            senderX.assertOpen();
            senderSigning.assertOpen();
            recipientX.assertOpen();
            assertEquals(1184, recipientPq.publicKey().length);
        }
    }

    @Test
    void constructorAndRequestValidateSignedHybridInvariantsAndSnapshotPairs() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        PublicHybridRecipientBuilder builder = realRecipientBuilder(x25519, mlkem);
        A256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        Ed25519Crypto ed25519 = new BouncyCastleEd25519Crypto();

        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridSignedSender(null, gcm, ed25519));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridSignedSender(builder, null, ed25519));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridSignedSender(builder, gcm, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridSignedSender(builder, gcm, ed25519, null));
        PublicHybridSignedSender sender = new PublicHybridSignedSender(builder, gcm, ed25519);
        assertNotNull(sender);
        assertThrows(IllegalArgumentException.class, () -> sender.send(null));

        X25519PrivateKeyHandle encryptionHandle = dummyX25519Handle();
        Ed25519PrivateKeyHandle signingHandle = dummyEd25519Handle();
        PublicHybridRecipientKeys pair = markerKeys(1, 2);
        assertThrows(IllegalArgumentException.class, () -> request(
                null, signingHandle, pair
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                null, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), null, TIMESTAMP, encryptionHandle, signingHandle, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP,
                encryptionHandle, signingHandle, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, -1, encryptionHandle, signingHandle, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, MAX_SAFE_JSON_INTEGER + 1,
                encryptionHandle, signingHandle, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> request(
                encryptionHandle, null, pair
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, null
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP,
                encryptionHandle, signingHandle, List.of()
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP,
                encryptionHandle, signingHandle, uniquePairs(33)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                Arrays.asList(pair, (PublicHybridRecipientKeys) null)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                List.of(pair, markerKeys(1, 2))
        ));

        ArrayList<PublicHybridRecipientKeys> callerPairs = new ArrayList<>();
        callerPairs.add(pair);
        PublicHybridSignedSender.Request snapshot = new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, MAX_SAFE_JSON_INTEGER,
                encryptionHandle, signingHandle, callerPairs
        );
        callerPairs.clear();
        assertEquals(1, snapshot.recipients().size());
        assertArrayEquals(
                pair.x25519PublicKey(), snapshot.recipients().get(0).x25519PublicKey()
        );
        assertArrayEquals(
                pair.mlkem768PublicKey(), snapshot.recipients().get(0).mlkem768PublicKey()
        );
        assertThrows(UnsupportedOperationException.class, () -> snapshot.recipients().clear());
        assertEquals(32, new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP,
                encryptionHandle, signingHandle, uniquePairs(32)
        ).recipients().size());
    }

    private static void assertRecipient(
            PublicRecipient recipient,
            byte[] x25519Public,
            byte[] mlkem768Public
    ) {
        assertEquals(X25519KeyId.derive(x25519Public), recipient.kid().x25519());
        assertEquals(MLKem768KeyId.derive(mlkem768Public), recipient.kid().mlkem768());
        assertEquals(40, recipient.encryptedKey().length);
        assertEquals(1088, recipient.ek().length);
    }

    private static void assertRecoveredAndVerified(
            X25519PrivateKeyHandle recipientX,
            MLKem768PrivateKeyHandle recipientPq,
            PublicRecipient recipient,
            byte[] senderXPublic,
            byte[] signingPublic,
            WindLetter letter,
            PublicHybridKekDeriver deriver,
            BouncyCastleA256KeyWrapCrypto keyWrap,
            BouncyCastleA256GcmCrypto gcm,
            BouncyCastleEd25519Crypto ed25519
    ) {
        byte[] ek = recipient.ek();
        byte[] kek = deriver.deriveForReceiver(
                recipientX, senderXPublic, recipientPq, ek
        );
        byte[] cek = null;
        byte[] aad = null;
        byte[] inner = null;
        try {
            cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            aad = new OuterAad().gcmInput(letter.protectedValue(), letter.aad());
            inner = gcm.decrypt(
                    cek, letter.iv(), aad, letter.ciphertext(), letter.tag()
            );
            try (SignedInnerCodec.Decoded decoded = new SignedInnerCodec().decode(inner)) {
                assertEquals(MESSAGE_ID, decoded.message().messageId());
                assertEquals(TIMESTAMP, decoded.message().timestamp());
                assertArrayEquals(PAYLOAD_BYTES, decoded.message().payload().data());
                assertEquals(
                        Ed25519KeyId.derive(signingPublic), decoded.message().signingKid()
                );
                new OuterBinding().verify(
                        decoded.message().binding(),
                        letter.protectedHeader(),
                        letter.recipients()
                );
                byte[] signingInput = decoded.signingInput();
                byte[] signature = decoded.signature();
                try {
                    assertTrue(ed25519.verify(signingPublic, signingInput, signature));
                } finally {
                    clear(signingInput, signature);
                }
            }
        } finally {
            clear(ek, kek, cek, aad, inner);
        }
    }

    private static void assertBadSignatureContract(byte[] providerSignature) {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        ReturningEd25519 ed25519 = new ReturningEd25519(providerSignature);
        SequenceSecureRandom random = new SequenceSecureRandom();
        RecordingGcm gcm = new RecordingGcm(new BouncyCastleA256GcmCrypto());
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                realRecipientBuilder(x25519, mlkem), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderX = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigning = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            assertThrows(IllegalStateException.class, () -> sender.send(request(
                    senderX, senderSigning, keys(recipientX, recipientPq)
            )));
            assertEquals(1, ed25519.signCalls);
            assertEquals(0, gcm.encryptCalls);
            assertAllZero(ed25519.references);
            assertAllZero(random.references);
            assertEquals(32, senderX.publicKey().length);
            assertEquals(32, senderSigning.publicKey().length);
        }
    }

    private static PublicHybridRecipientBuilder realRecipientBuilder(
            BouncyCastleX25519Crypto x25519,
            BouncyCastleMLKem768Crypto mlkem
    ) {
        return new PublicHybridRecipientBuilder(
                new PublicHybridKekDeriver(
                        x25519, mlkem, new BouncyCastleHkdfCrypto()
                ),
                new BouncyCastleA256KeyWrapCrypto()
        );
    }

    private static PublicHybridSignedSender.Request request(
            X25519PrivateKeyHandle senderX,
            Ed25519PrivateKeyHandle senderSigning,
            PublicHybridRecipientKeys recipient
    ) {
        return new PublicHybridSignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP,
                senderX, senderSigning, List.of(recipient)
        );
    }

    private static PublicHybridRecipientKeys keys(
            X25519PrivateKeyHandle x25519,
            MLKem768PrivateKeyHandle mlkem768
    ) {
        return new PublicHybridRecipientKeys(x25519.publicKey(), mlkem768.publicKey());
    }

    private static PublicHybridRecipientKeys markerKeys(int xMarker, int pqMarker) {
        byte[] x25519 = new byte[32];
        byte[] mlkem768 = new byte[1184];
        x25519[0] = (byte) xMarker;
        mlkem768[0] = (byte) pqMarker;
        return new PublicHybridRecipientKeys(x25519, mlkem768);
    }

    private static List<PublicHybridRecipientKeys> uniquePairs(int count) {
        List<PublicHybridRecipientKeys> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            result.add(markerKeys(index + 1, 100 + index));
        }
        return result;
    }

    private static ProtocolPayload payload() {
        return new ProtocolPayload(
                "application/octet-stream", PAYLOAD_BYTES, PAYLOAD_BYTES.length
        );
    }

    private static X25519PrivateKeyHandle dummyX25519Handle() {
        return new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
            }
        };
    }

    private static Ed25519PrivateKeyHandle dummyEd25519Handle() {
        return new Ed25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
            }
        };
    }

    private static void assertAllZero(List<byte[]> values) {
        for (byte[] value : values) {
            assertNotNull(value);
            assertTrue(allZero(value));
        }
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
        }
    }

    private static final class SequenceSecureRandom extends SecureRandom {
        private final List<byte[]> references = new ArrayList<>();
        private int calls;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, (byte) (0x41 + calls));
            references.add(bytes);
            calls++;
        }
    }

    private static class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        protected final List<byte[]> references = new ArrayList<>();
        protected int encryptCalls;

        private RecordingGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            references.add(key);
            references.add(iv);
            references.add(aad);
            references.add(plaintext);
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag
        ) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
        }
    }

    private static final class FailingGcm extends RecordingGcm {
        private FailingGcm() {
            super(new BouncyCastleA256GcmCrypto());
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            references.add(key);
            references.add(iv);
            references.add(aad);
            references.add(plaintext);
            throw new CryptoOperationException("intentional GCM failure");
        }
    }

    private static class RecordingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        protected final List<byte[]> references = new ArrayList<>();
        private byte[] signingInputSnapshot;
        private byte[] signatureSnapshot;
        protected int signCalls;

        private RecordingEd25519(Ed25519Crypto delegate) {
            this.delegate = delegate;
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
            references.add(message);
            signingInputSnapshot = message.clone();
            byte[] signature = delegate.sign(privateKey, message);
            references.add(signature);
            signatureSnapshot = signature.clone();
            return signature;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return delegate.verify(publicKey, message, signature);
        }
    }

    private static final class ReturningEd25519 implements Ed25519Crypto {
        private final byte[] result;
        private final List<byte[]> references = new ArrayList<>();
        private int signCalls;

        private ReturningEd25519(byte[] result) {
            this.result = result;
        }

        @Override
        public Ed25519PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            signCalls++;
            references.add(message);
            if (result != null) {
                references.add(result);
            }
            return result;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class ThrowingEd25519 implements Ed25519Crypto {
        private final List<byte[]> references = new ArrayList<>();
        private int signCalls;

        @Override
        public Ed25519PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            signCalls++;
            references.add(message);
            throw new CryptoOperationException("intentional signing failure");
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class TrackingX25519Crypto implements X25519Crypto {
        private final BouncyCastleX25519Crypto delegate = new BouncyCastleX25519Crypto();

        @Override
        public TrackingX25519Handle generatePrivateKey() {
            return new TrackingX25519Handle(delegate.generatePrivateKey());
        }

        @Override
        public TrackingX25519Handle importPrivateKey(byte[] privateKey) {
            return new TrackingX25519Handle(delegate.importPrivateKey(privateKey));
        }

        @Override
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey, byte[] peerPublicKey
        ) {
            if (!(privateKey instanceof TrackingX25519Handle tracking)) {
                throw new IllegalArgumentException("unexpected X25519 handle");
            }
            return delegate.deriveSharedSecret(tracking.delegate, peerPublicKey);
        }
    }

    private static final class TrackingX25519Handle implements X25519PrivateKeyHandle {
        private final X25519PrivateKeyHandle delegate;
        private final List<byte[]> capturedPublicKeys = new ArrayList<>();

        private TrackingX25519Handle(X25519PrivateKeyHandle delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] publicKey() {
            byte[] publicKey = delegate.publicKey();
            capturedPublicKeys.add(publicKey);
            return publicKey;
        }

        private void clearCapturedPublicKeys() {
            capturedPublicKeys.clear();
        }

        private void assertOpen() {
            byte[] publicKey = delegate.publicKey();
            try {
                assertEquals(32, publicKey.length);
            } finally {
                clear(publicKey);
            }
        }

        @Override
        public void close() {
            delegate.close();
        }
    }

    private static final class TrackingEd25519Crypto implements Ed25519Crypto {
        private final BouncyCastleEd25519Crypto delegate = new BouncyCastleEd25519Crypto();
        private final List<byte[]> references = new ArrayList<>();
        private int signCalls;

        @Override
        public TrackingEd25519Handle generatePrivateKey() {
            return new TrackingEd25519Handle(delegate.generatePrivateKey());
        }

        @Override
        public TrackingEd25519Handle importPrivateKey(byte[] privateKey) {
            return new TrackingEd25519Handle(delegate.importPrivateKey(privateKey));
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            if (!(privateKey instanceof TrackingEd25519Handle tracking)) {
                throw new IllegalArgumentException("unexpected Ed25519 handle");
            }
            signCalls++;
            references.add(message);
            byte[] signature = delegate.sign(tracking.delegate, message);
            references.add(signature);
            return signature;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return delegate.verify(publicKey, message, signature);
        }
    }

    private static final class TrackingEd25519Handle implements Ed25519PrivateKeyHandle {
        private final Ed25519PrivateKeyHandle delegate;
        private final List<byte[]> capturedPublicKeys = new ArrayList<>();

        private TrackingEd25519Handle(Ed25519PrivateKeyHandle delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] publicKey() {
            byte[] publicKey = delegate.publicKey();
            capturedPublicKeys.add(publicKey);
            return publicKey;
        }

        private void assertOpen() {
            byte[] publicKey = delegate.publicKey();
            try {
                assertEquals(32, publicKey.length);
            } finally {
                clear(publicKey);
            }
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
