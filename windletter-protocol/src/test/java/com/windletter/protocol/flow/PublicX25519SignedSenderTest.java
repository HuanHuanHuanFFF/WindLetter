package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicX25519SignedSenderTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final byte[] PAYLOAD_BYTES = {0, 1, 2, (byte) 0xff};

    @Test
    void sendsStrictTwoRecipientSignedWireAndBothRecipientsRecoverAndVerifyIt() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(x25519, hkdf);
        PublicX25519RecipientBuilder recipientBuilder = new PublicX25519RecipientBuilder(
                kekDeriver, keyWrap
        );
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                recipientBuilder, gcm, ed25519
        );
        ProtocolPayload payload = payload();

        try (X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigningKey = ed25519.generatePrivateKey();
             X25519PrivateKeyHandle firstRecipientKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle secondRecipientKey = x25519.generatePrivateKey()) {
            byte[] senderEncryptionPublic = senderEncryptionKey.publicKey();
            byte[] senderSigningPublic = senderSigningKey.publicKey();
            PublicX25519SignedSender.Result result = sender.send(
                    new PublicX25519SignedSender.Request(
                            payload,
                            MESSAGE_ID,
                            TIMESTAMP,
                            senderEncryptionKey,
                            senderSigningKey,
                            List.of(firstRecipientKey.publicKey(), secondRecipientKey.publicKey())
                    )
            );

            WindLetter parsed = new JacksonOuterWireParser().parse(result.wireJson());
            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+jws", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("public", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519", parsed.protectedHeader().keyAlg());
            SenderKid senderKid = assertInstanceOf(
                    SenderKid.class, parsed.protectedHeader().senderInfo()
            );
            assertEquals(X25519KeyId.derive(senderEncryptionPublic), senderKid.x25519());
            assertEquals(
                    Base64Url.encode(JcsCanonicalizer.canonicalize(
                            OuterJsonMapper.toProtectedJson(parsed.protectedHeader())
                    )),
                    parsed.protectedValue()
            );
            assertEquals(2, parsed.recipients().size());
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
            for (int index = 0; index < parsed.recipients().size(); index++) {
                PublicRecipient recipient = assertInstanceOf(
                        PublicRecipient.class, parsed.recipients().get(index)
                );
                assertNull(recipient.ek());
                assertNull(recipient.kid().mlkem768());
                assertEquals(40, recipient.encryptedKey().length);
            }

            assertRecoveredAndVerified(
                    firstRecipientKey,
                    (PublicRecipient) parsed.recipients().get(0),
                    senderEncryptionPublic,
                    senderSigningPublic,
                    payload,
                    parsed,
                    kekDeriver,
                    keyWrap,
                    gcm,
                    ed25519
            );
            assertRecoveredAndVerified(
                    secondRecipientKey,
                    (PublicRecipient) parsed.recipients().get(1),
                    senderEncryptionPublic,
                    senderSigningPublic,
                    payload,
                    parsed,
                    kekDeriver,
                    keyWrap,
                    gcm,
                    ed25519
            );
            assertArrayEquals(parsed.iv(), result.message().iv());
            assertArrayEquals(parsed.ciphertext(), result.message().ciphertext());
            assertArrayEquals(parsed.tag(), result.message().tag());
            assertEquals(1, occurrences(result.wireJson(), "\"ciphertext\""));
            assertEquals(32, senderEncryptionKey.publicKey().length);
            assertEquals(32, senderSigningKey.publicKey().length);
        }
    }

    @Test
    void consecutiveEquivalentSendsUseFreshCekAndIvAndOneSignatureAndCiphertextEach() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        RecordingEd25519Crypto ed25519 = new RecordingEd25519Crypto(realEd25519);
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                realRecipientBuilder(x25519), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigningKey = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            PublicX25519SignedSender.Request request = new PublicX25519SignedSender.Request(
                    payload(), MESSAGE_ID, TIMESTAMP, senderEncryptionKey, senderSigningKey,
                    List.of(recipient.publicKey())
            );

            PublicX25519SignedSender.Result first = sender.send(request);
            PublicX25519SignedSender.Result second = sender.send(request);

            assertEquals(2, ed25519.signCalls);
            assertEquals(2, gcm.encryptCalls);
            assertFalse(Arrays.equals(first.message().iv(), second.message().iv()));
            assertFalse(Arrays.equals(first.message().ciphertext(), second.message().ciphertext()));
            assertNotEquals(first.wireJson(), second.wireJson());
            assertArrayEquals(random.snapshots.get(1), first.message().iv());
            assertArrayEquals(random.snapshots.get(3), second.message().iv());
            assertEquals(1, occurrences(first.wireJson(), "\"ciphertext\""));
            assertEquals(1, occurrences(second.wireJson(), "\"ciphertext\""));
            assertAllZero(random.references);
            assertAllZero(ed25519.capturedReferences());
            assertAllZero(gcm.capturedReferences());
            assertEquals(32, senderEncryptionKey.publicKey().length);
            assertEquals(32, senderSigningKey.publicKey().length);
        }
    }

    @Test
    void requestValidatesProtocolBoundsAndDeepSnapshotsRecipientKeys() {
        ProtocolPayload payload = payload();
        X25519PrivateKeyHandle encryptionHandle = dummyX25519Handle();
        Ed25519PrivateKeyHandle signingHandle = dummyEd25519Handle();
        byte[] key = filled(32, 1);

        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                null, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, null, TIMESTAMP, encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, "123E4567-E89B-42D3-A456-426614174000", TIMESTAMP,
                encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP,
                encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, "123e4567-e89b-42d3-7456-426614174000", TIMESTAMP,
                encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, -1, encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER + 1,
                encryptionHandle, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, null, signingHandle, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, null, List.of(key)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, null
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, List.of()
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, uniqueKeys(33)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                Arrays.asList((byte[]) null)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                List.of(new byte[31])
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                List.of(new byte[33])
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle,
                List.of(key, key.clone())
        ));

        ArrayList<byte[]> callerList = new ArrayList<>();
        byte[] callerKey = filled(32, 0x55);
        byte[] expected = callerKey.clone();
        callerList.add(callerKey);
        PublicX25519SignedSender.Request snapshot = new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER,
                encryptionHandle, signingHandle, callerList
        );
        Arrays.fill(callerKey, (byte) 0);
        callerList.clear();
        assertEquals(1, snapshot.recipientPublicKeys().size());
        assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
        byte[] accessorValue = snapshot.recipientPublicKeys().get(0);
        Arrays.fill(accessorValue, (byte) 0);
        assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
        assertEquals(32, new PublicX25519SignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, encryptionHandle, signingHandle, uniqueKeys(32)
        ).recipientPublicKeys().size());
    }

    @Test
    void validatesDependenciesAndTopLevelRequest() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519RecipientBuilder builder = realRecipientBuilder(x25519);
        A256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        Ed25519Crypto ed25519 = new BouncyCastleEd25519Crypto();

        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519SignedSender(null, gcm, ed25519));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519SignedSender(builder, null, ed25519));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519SignedSender(builder, gcm, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519SignedSender(builder, gcm, ed25519, null));
        PublicX25519SignedSender sender = new PublicX25519SignedSender(builder, gcm, ed25519);
        assertNotNull(sender);
        assertThrows(IllegalArgumentException.class, () -> sender.send(null));
    }

    @Test
    void rejectsNullShortAndLongProviderSignaturesAndClearsEveryProducedReference() {
        assertBadSignatureContract(null);
        assertBadSignatureContract(new byte[63]);
        assertBadSignatureContract(new byte[65]);
    }

    @Test
    void signingFailureClearsGeneratedSecretsAndSigningInputAndLeavesBothHandlesOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        ThrowingEd25519Crypto ed25519 = new ThrowingEd25519Crypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                realRecipientBuilder(x25519), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigningKey = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class, () -> sender.send(request(
                    senderEncryptionKey, senderSigningKey, recipient.publicKey()
            )));

            assertEquals(1, ed25519.signCalls);
            assertEquals(0, gcm.encryptCalls);
            assertAllZero(ed25519.capturedReferences());
            assertAllZero(random.references);
            assertEquals(32, senderEncryptionKey.publicKey().length);
            assertEquals(32, senderSigningKey.publicKey().length);
        }
    }

    @Test
    void gcmFailureAfterSigningClearsCekIvAadInnerSigningInputAndSignature() {
        TrackingX25519Crypto x25519 = new TrackingX25519Crypto();
        TrackingEd25519Crypto ed25519 = new TrackingEd25519Crypto();
        FailingGcmCrypto gcm = new FailingGcmCrypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                new PublicX25519RecipientBuilder(
                        new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                        new BouncyCastleA256KeyWrapCrypto()
                ),
                gcm,
                ed25519,
                random
        );
        try (TrackingX25519Handle senderEncryptionKey = x25519.generateTrackingPrivateKey();
             TrackingEd25519Handle senderSigningKey = ed25519.generateTrackingPrivateKey();
             TrackingX25519Handle recipient = x25519.generateTrackingPrivateKey()) {
            byte[] callerRecipientKey = recipient.publicKey();
            recipient.clearCapturedPublicKeys();
            byte[] expectedRecipientKey = callerRecipientKey.clone();

            assertThrows(CryptoOperationException.class, () -> sender.send(request(
                    senderEncryptionKey, senderSigningKey, callerRecipientKey
            )));

            assertEquals(1, ed25519.signCalls);
            assertEquals(1, gcm.encryptCalls);
            assertAllZero(ed25519.capturedReferences());
            assertAllZero(gcm.capturedReferences());
            assertAllZero(random.references);
            assertAllZero(senderEncryptionKey.capturedPublicKeys());
            assertAllZero(senderSigningKey.capturedPublicKeys());
            assertArrayEquals(expectedRecipientKey, callerRecipientKey);
            senderEncryptionKey.assertOpen();
            senderSigningKey.assertOpen();
        }
    }

    @Test
    void recipientFailureBeforeSigningClearsGeneratedSecretsAndLeavesBothHandlesOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        RecordingEd25519Crypto ed25519 = new RecordingEd25519Crypto(realEd25519);
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                realRecipientBuilder(x25519), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigningKey = realEd25519.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class, () -> sender.send(request(
                    senderEncryptionKey, senderSigningKey, new byte[32]
            )));

            assertEquals(0, ed25519.signCalls);
            assertEquals(0, gcm.encryptCalls);
            assertAllZero(random.references);
            assertEquals(32, senderEncryptionKey.publicKey().length);
            assertEquals(32, senderSigningKey.publicKey().length);
        }
    }

    @Test
    void successClearsDirectPublicKeySnapshotsAndAllCryptoInputReferences() {
        TrackingX25519Crypto x25519 = new TrackingX25519Crypto();
        TrackingEd25519Crypto ed25519 = new TrackingEd25519Crypto();
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                new PublicX25519RecipientBuilder(
                        new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                        new BouncyCastleA256KeyWrapCrypto()
                ),
                gcm,
                ed25519,
                random
        );
        try (TrackingX25519Handle senderEncryptionKey = x25519.generateTrackingPrivateKey();
             TrackingEd25519Handle senderSigningKey = ed25519.generateTrackingPrivateKey();
             TrackingX25519Handle recipient = x25519.generateTrackingPrivateKey()) {
            byte[] recipientPublicKey = recipient.publicKey();
            recipient.clearCapturedPublicKeys();

            PublicX25519SignedSender.Result result = sender.send(request(
                    senderEncryptionKey, senderSigningKey, recipientPublicKey
            ));

            assertNotNull(new JacksonOuterWireParser().parse(result.wireJson()));
            assertAllZero(senderEncryptionKey.capturedPublicKeys());
            assertAllZero(senderSigningKey.capturedPublicKeys());
            assertAllZero(ed25519.capturedReferences());
            assertAllZero(gcm.capturedReferences());
            assertAllZero(random.references);
            assertArrayEquals(recipient.publicKeyWithoutCapture(), recipientPublicKey);
            senderEncryptionKey.assertOpen();
            senderSigningKey.assertOpen();
        }
    }

    private static void assertRecoveredAndVerified(
            X25519PrivateKeyHandle recipientKey,
            PublicRecipient recipient,
            byte[] senderEncryptionPublic,
            byte[] senderSigningPublic,
            ProtocolPayload expectedPayload,
            WindLetter letter,
            PublicX25519KekDeriver kekDeriver,
            BouncyCastleA256KeyWrapCrypto keyWrap,
            BouncyCastleA256GcmCrypto gcm,
            BouncyCastleEd25519Crypto ed25519
    ) {
        byte[] kek = kekDeriver.derive(recipientKey, senderEncryptionPublic);
        byte[] cek = null;
        byte[] plaintext = null;
        try {
            cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            plaintext = gcm.decrypt(
                    cek,
                    letter.iv(),
                    new OuterAad().gcmInput(letter.protectedValue(), letter.aad()),
                    letter.ciphertext(),
                    letter.tag()
            );
            try (SignedInnerCodec.Decoded decoded = new SignedInnerCodec().decode(plaintext)) {
                assertEquals(MESSAGE_ID, decoded.message().messageId());
                assertEquals(TIMESTAMP, decoded.message().timestamp());
                assertEquals(expectedPayload.contentType(), decoded.message().payload().contentType());
                assertArrayEquals(expectedPayload.data(), decoded.message().payload().data());
                assertEquals(Ed25519KeyId.derive(senderSigningPublic), decoded.message().signingKid());
                new OuterBinding().verify(
                        decoded.message().binding(), letter.protectedHeader(), letter.recipients()
                );
                byte[] signingInput = decoded.signingInput();
                byte[] signature = decoded.signature();
                try {
                    assertTrue(ed25519.verify(senderSigningPublic, signingInput, signature));
                } finally {
                    Arrays.fill(signingInput, (byte) 0);
                    Arrays.fill(signature, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(kek, (byte) 0);
            if (cek != null) {
                Arrays.fill(cek, (byte) 0);
            }
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private static PublicX25519RecipientBuilder realRecipientBuilder(
            BouncyCastleX25519Crypto x25519
    ) {
        return new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                new BouncyCastleA256KeyWrapCrypto()
        );
    }

    private static PublicX25519SignedSender.Request request(
            X25519PrivateKeyHandle senderEncryptionKey,
            Ed25519PrivateKeyHandle senderSigningKey,
            byte[] recipientPublicKey
    ) {
        return new PublicX25519SignedSender.Request(
                payload(), MESSAGE_ID, TIMESTAMP, senderEncryptionKey, senderSigningKey,
                List.of(recipientPublicKey)
        );
    }

    private static void assertBadSignatureContract(byte[] providerSignature) {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleEd25519Crypto realEd25519 = new BouncyCastleEd25519Crypto();
        ReturningEd25519Crypto ed25519 = new ReturningEd25519Crypto(providerSignature);
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519SignedSender sender = new PublicX25519SignedSender(
                realRecipientBuilder(x25519), gcm, ed25519, random
        );
        try (X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
             Ed25519PrivateKeyHandle senderSigningKey = realEd25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            assertThrows(IllegalStateException.class, () -> sender.send(request(
                    senderEncryptionKey, senderSigningKey, recipient.publicKey()
            )));

            assertEquals(1, ed25519.signCalls);
            assertEquals(0, gcm.encryptCalls);
            assertAllZero(ed25519.capturedReferences());
            assertAllZero(random.references);
            assertEquals(32, senderEncryptionKey.publicKey().length);
            assertEquals(32, senderSigningKey.publicKey().length);
        }
    }

    private static ProtocolPayload payload() {
        return new ProtocolPayload("application/octet-stream", PAYLOAD_BYTES, PAYLOAD_BYTES.length);
    }

    private static X25519PrivateKeyHandle dummyX25519Handle() {
        return new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return filled(32, 0x6e);
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
                return filled(32, 0x5d);
            }

            @Override
            public void close() {
            }
        };
    }

    private static List<byte[]> uniqueKeys(int count) {
        List<byte[]> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            byte[] key = new byte[32];
            key[0] = (byte) (index + 1);
            result.add(key);
        }
        return result;
    }

    private static byte[] filled(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static int occurrences(String text, String value) {
        int count = 0;
        int from = 0;
        while ((from = text.indexOf(value, from)) >= 0) {
            count++;
            from += value.length();
        }
        return count;
    }

    private static void assertAllZero(List<byte[]> values) {
        for (byte[] value : values) {
            assertTrue(allZero(value));
        }
    }

    private static boolean allZero(byte[] value) {
        if (value == null) {
            return false;
        }
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static final class SequenceSecureRandom extends SecureRandom {
        private final List<byte[]> references = new ArrayList<>();
        private final List<byte[]> snapshots = new ArrayList<>();
        private int calls;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, (byte) (0x41 + calls));
            references.add(bytes);
            snapshots.add(bytes.clone());
            calls++;
        }
    }

    private static class RecordingGcmCrypto implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        protected final List<byte[]> references = new ArrayList<>();
        protected int encryptCalls;

        private RecordingGcmCrypto(A256GcmCrypto delegate) {
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

        protected List<byte[]> capturedReferences() {
            return List.copyOf(references);
        }
    }

    private static class RecordingEd25519Crypto implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final List<byte[]> references = new ArrayList<>();
        protected int signCalls;

        private RecordingEd25519Crypto(Ed25519Crypto delegate) {
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
            byte[] signature = delegate.sign(privateKey, message);
            references.add(signature);
            return signature;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return delegate.verify(publicKey, message, signature);
        }

        protected List<byte[]> capturedReferences() {
            return List.copyOf(references);
        }
    }

    private static final class ReturningEd25519Crypto implements Ed25519Crypto {
        private final byte[] result;
        private final List<byte[]> references = new ArrayList<>();
        private int signCalls;

        private ReturningEd25519Crypto(byte[] result) {
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

        private List<byte[]> capturedReferences() {
            return List.copyOf(references);
        }
    }

    private static final class ThrowingEd25519Crypto implements Ed25519Crypto {
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
            throw new CryptoOperationException("intentional Ed25519 signing failure");
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            throw new UnsupportedOperationException();
        }

        private List<byte[]> capturedReferences() {
            return List.copyOf(references);
        }
    }

    private static final class FailingGcmCrypto extends RecordingGcmCrypto {
        private FailingGcmCrypto() {
            super(new BouncyCastleA256GcmCrypto());
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            super.encryptCalls++;
            super.references.add(key);
            super.references.add(iv);
            super.references.add(aad);
            super.references.add(plaintext);
            throw new CryptoOperationException("intentional GCM failure");
        }
    }

    private static final class TrackingX25519Crypto implements X25519Crypto {
        private final BouncyCastleX25519Crypto delegate = new BouncyCastleX25519Crypto();

        @Override
        public TrackingX25519Handle generatePrivateKey() {
            return new TrackingX25519Handle(delegate.generatePrivateKey());
        }

        private TrackingX25519Handle generateTrackingPrivateKey() {
            return generatePrivateKey();
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

        private byte[] publicKeyWithoutCapture() {
            return delegate.publicKey();
        }

        private List<byte[]> capturedPublicKeys() {
            return List.copyOf(capturedPublicKeys);
        }

        private void clearCapturedPublicKeys() {
            capturedPublicKeys.clear();
        }

        private void assertOpen() {
            byte[] publicKey = delegate.publicKey();
            try {
                assertEquals(32, publicKey.length);
            } finally {
                Arrays.fill(publicKey, (byte) 0);
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

        private TrackingEd25519Handle generateTrackingPrivateKey() {
            return generatePrivateKey();
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

        private List<byte[]> capturedReferences() {
            return List.copyOf(references);
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

        private List<byte[]> capturedPublicKeys() {
            return List.copyOf(capturedPublicKeys);
        }

        private void assertOpen() {
            byte[] publicKey = delegate.publicKey();
            try {
                assertEquals(32, publicKey.length);
            } finally {
                Arrays.fill(publicKey, (byte) 0);
            }
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
