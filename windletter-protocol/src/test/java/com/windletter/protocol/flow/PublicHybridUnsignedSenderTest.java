package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.UnsignedInnerCodec;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridUnsignedSenderTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;

    @Test
    void sendsStrictTwoRecipientHybridWireWithIndependentEncapsulations() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                new PublicHybridRecipientBuilder(deriver, keyWrap), gcm
        );

        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
             X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey()) {
            byte[] firstXPublic = firstX.publicKey();
            byte[] firstPqPublic = firstPq.publicKey();
            byte[] secondXPublic = secondX.publicKey();
            byte[] secondPqPublic = secondPq.publicKey();
            PublicHybridUnsignedSender.Result result = sender.send(
                    new PublicHybridUnsignedSender.Request(
                            payload(), MESSAGE_ID, TIMESTAMP, senderKey,
                            List.of(
                                    new PublicHybridRecipientKeys(firstXPublic, firstPqPublic),
                                    new PublicHybridRecipientKeys(secondXPublic, secondPqPublic)
                            )
                    )
            );
            WindLetter letter = new JacksonOuterWireParser().parse(result.wireJson());

            assertEquals("wind+jwe", letter.protectedHeader().typ());
            assertEquals("wind+inner", letter.protectedHeader().cty());
            assertEquals("1.0", letter.protectedHeader().ver());
            assertEquals("public", letter.protectedHeader().windMode());
            assertEquals("A256GCM", letter.protectedHeader().enc());
            assertEquals("X25519ML-KEM-768", letter.protectedHeader().keyAlg());
            SenderKid senderKid = assertInstanceOf(
                    SenderKid.class, letter.protectedHeader().senderInfo()
            );
            assertEquals(X25519KeyId.derive(senderKey.publicKey()), senderKid.x25519());
            assertEquals(
                    Base64Url.encode(JcsCanonicalizer.canonicalize(
                            OuterJsonMapper.toProtectedJson(letter.protectedHeader())
                    )),
                    letter.protectedValue()
            );
            assertEquals(2, letter.recipients().size());
            PublicRecipient first = assertInstanceOf(
                    PublicRecipient.class, letter.recipients().get(0)
            );
            PublicRecipient second = assertInstanceOf(
                    PublicRecipient.class, letter.recipients().get(1)
            );
            assertEquals(X25519KeyId.derive(firstXPublic), first.kid().x25519());
            assertEquals(MLKem768KeyId.derive(firstPqPublic), first.kid().mlkem768());
            assertEquals(X25519KeyId.derive(secondXPublic), second.kid().x25519());
            assertEquals(MLKem768KeyId.derive(secondPqPublic), second.kid().mlkem768());
            assertEquals(40, first.encryptedKey().length);
            assertEquals(40, second.encryptedKey().length);
            assertEquals(1088, first.ek().length);
            assertEquals(1088, second.ek().length);
            assertFalse(Arrays.equals(first.ek(), second.ek()));
            assertEquals(new OuterAad().compute(letter.recipients()), letter.aad());

            UnsignedInnerCodec.Message firstInner = decryptFor(
                    firstX, firstPq, first, senderKey.publicKey(), letter, deriver, keyWrap, gcm
            );
            UnsignedInnerCodec.Message secondInner = decryptFor(
                    secondX, secondPq, second, senderKey.publicKey(), letter, deriver, keyWrap, gcm
            );
            assertInner(firstInner, letter);
            assertInner(secondInner, letter);
            assertArrayEquals(letter.iv(), result.message().iv());
            assertArrayEquals(letter.ciphertext(), result.message().ciphertext());
            assertArrayEquals(letter.tag(), result.message().tag());
            assertEquals(32, senderKey.publicKey().length);
        }
    }

    @Test
    void consecutiveEquivalentSendsUseFreshCekIvAndIndependentEncapsulations() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        RecordingGcm gcm = new RecordingGcm(new BouncyCastleA256GcmCrypto());
        PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                realRecipientBuilder(x25519, mlkem), gcm, random
        );
        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            PublicHybridUnsignedSender.Request request = new PublicHybridUnsignedSender.Request(
                    payload(), MESSAGE_ID, TIMESTAMP, senderKey,
                    List.of(new PublicHybridRecipientKeys(
                            recipientX.publicKey(), recipientPq.publicKey()
                    ))
            );

            PublicHybridUnsignedSender.Result first = sender.send(request);
            PublicHybridUnsignedSender.Result second = sender.send(request);

            assertEquals(2, gcm.encryptCalls);
            assertFalse(Arrays.equals(first.message().iv(), second.message().iv()));
            assertFalse(Arrays.equals(first.message().ciphertext(), second.message().ciphertext()));
            PublicRecipient firstRecipient = (PublicRecipient) first.message().recipients().get(0);
            PublicRecipient secondRecipient = (PublicRecipient) second.message().recipients().get(0);
            assertFalse(Arrays.equals(firstRecipient.ek(), secondRecipient.ek()));
            assertNotEquals(first.wireJson(), second.wireJson());
            assertTrue(random.references.stream().allMatch(PublicHybridUnsignedSenderTest::allZero));
            assertEquals(32, senderKey.publicKey().length);
        }
    }

    @Test
    void requestValidatesBoundsAndSnapshotsCompleteRecipientPairs() {
        ProtocolPayload payload = payload();
        X25519PrivateKeyHandle senderKey = dummyX25519Handle();
        PublicHybridRecipientKeys pair = keys(1, 2);

        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                null, MESSAGE_ID, TIMESTAMP, senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, null, TIMESTAMP, senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, "123E4567-E89B-42D3-A456-426614174000", TIMESTAMP,
                senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP,
                senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, -1, senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER + 1, senderKey, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, null, List.of(pair)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey, null
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey, List.of()
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey, uniquePairs(33)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey,
                Arrays.asList(pair, (PublicHybridRecipientKeys) null)
        ));
        assertThrows(IllegalArgumentException.class, () -> new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey, List.of(pair, keys(1, 2))
        ));

        ArrayList<PublicHybridRecipientKeys> callerList = new ArrayList<>();
        callerList.add(pair);
        PublicHybridUnsignedSender.Request snapshot = new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER, senderKey, callerList
        );
        callerList.clear();
        assertEquals(1, snapshot.recipients().size());
        assertArrayEquals(pair.x25519PublicKey(), snapshot.recipients().get(0).x25519PublicKey());
        assertArrayEquals(pair.mlkem768PublicKey(), snapshot.recipients().get(0).mlkem768PublicKey());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.recipients().clear());
        assertEquals(32, new PublicHybridUnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, senderKey, uniquePairs(32)
        ).recipients().size());
    }

    @Test
    void gcmFailureClearsOwnedInputsAndLeavesAllBorrowedHandlesOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        FailingGcm gcm = new FailingGcm();
        PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                realRecipientBuilder(x25519, mlkem), gcm, random
        );
        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class, () -> sender.send(
                    new PublicHybridUnsignedSender.Request(
                            payload(), MESSAGE_ID, TIMESTAMP, senderKey,
                            List.of(new PublicHybridRecipientKeys(
                                    recipientX.publicKey(), recipientPq.publicKey()
                            ))
                    )
            ));

            assertEquals(1, gcm.encryptCalls);
            assertTrue(random.references.stream().allMatch(PublicHybridUnsignedSenderTest::allZero));
            assertTrue(gcm.capturedReferences().stream()
                    .allMatch(PublicHybridUnsignedSenderTest::allZero));
            assertEquals(32, senderKey.publicKey().length);
            assertEquals(32, recipientX.publicKey().length);
            assertEquals(1184, recipientPq.publicKey().length);
        }
    }

    @Test
    void validatesConstructorDependencies() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        PublicHybridRecipientBuilder builder = realRecipientBuilder(x25519, mlkem);
        A256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();

        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridUnsignedSender(null, gcm));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridUnsignedSender(builder, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridUnsignedSender(builder, gcm, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridUnsignedSender(builder, gcm).send(null));
        assertNotNull(new PublicHybridUnsignedSender(builder, gcm));
    }

    private static PublicHybridRecipientBuilder realRecipientBuilder(
            BouncyCastleX25519Crypto x25519,
            BouncyCastleMLKem768Crypto mlkem
    ) {
        return new PublicHybridRecipientBuilder(
                new PublicHybridKekDeriver(x25519, mlkem, new BouncyCastleHkdfCrypto()),
                new BouncyCastleA256KeyWrapCrypto()
        );
    }

    private static UnsignedInnerCodec.Message decryptFor(
            X25519PrivateKeyHandle recipientX,
            MLKem768PrivateKeyHandle recipientPq,
            PublicRecipient recipient,
            byte[] senderPublic,
            WindLetter letter,
            PublicHybridKekDeriver deriver,
            BouncyCastleA256KeyWrapCrypto keyWrap,
            BouncyCastleA256GcmCrypto gcm
    ) {
        byte[] ek = recipient.ek();
        byte[] kek = deriver.deriveForReceiver(recipientX, senderPublic, recipientPq, ek);
        byte[] cek = keyWrap.unwrap(kek, recipient.encryptedKey());
        byte[] aad = new OuterAad().gcmInput(letter.protectedValue(), letter.aad());
        byte[] plaintext = null;
        try {
            plaintext = gcm.decrypt(cek, letter.iv(), aad, letter.ciphertext(), letter.tag());
            return new UnsignedInnerCodec().decode(plaintext);
        } finally {
            Arrays.fill(senderPublic, (byte) 0);
            Arrays.fill(ek, (byte) 0);
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(cek, (byte) 0);
            Arrays.fill(aad, (byte) 0);
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private static void assertInner(UnsignedInnerCodec.Message inner, WindLetter letter) {
        assertEquals(MESSAGE_ID, inner.messageId());
        assertEquals(TIMESTAMP, inner.timestamp());
        assertEquals(payload().contentType(), inner.payload().contentType());
        assertArrayEquals(payload().data(), inner.payload().data());
        new OuterBinding().verify(
                inner.binding(), letter.protectedHeader(), letter.recipients()
        );
    }

    private static PublicHybridRecipientKeys keys(int xMarker, int pqMarker) {
        byte[] x = new byte[32];
        byte[] pq = new byte[1184];
        x[0] = (byte) xMarker;
        pq[0] = (byte) pqMarker;
        return new PublicHybridRecipientKeys(x, pq);
    }

    private static List<PublicHybridRecipientKeys> uniquePairs(int count) {
        List<PublicHybridRecipientKeys> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(keys(i + 1, 100 + i));
        }
        return result;
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

    private static ProtocolPayload payload() {
        byte[] data = {0, (byte) 0xff, (byte) 0xc3, 0x28};
        return new ProtocolPayload("application/octet-stream", data, data.length);
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
        protected int encryptCalls;
        private byte[] key;
        private byte[] iv;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            capture(key, iv, aad, plaintext);
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag
        ) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
        }

        protected void capture(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            this.key = key;
            this.iv = iv;
            this.aad = aad;
            this.plaintext = plaintext;
        }

        protected List<byte[]> capturedReferences() {
            return List.of(key, iv, aad, plaintext);
        }
    }

    private static final class FailingGcm extends RecordingGcm {
        private FailingGcm() {
            super(new BouncyCastleA256GcmCrypto());
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            super.encryptCalls++;
            super.capture(key, iv, aad, plaintext);
            throw new CryptoOperationException("intentional GCM failure");
        }
    }
}
