package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicX25519UnsignedSenderTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final byte[] PAYLOAD_BYTES = {0, 1, 2, (byte) 0xff, 4};

    @Test
    void sendsStrictTwoRecipientWireWithExactProfileAadBindingAndRealCrypto() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto realGcm = new BouncyCastleA256GcmCrypto();
        PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(x25519, hkdf);
        PublicX25519RecipientBuilder recipientBuilder = new PublicX25519RecipientBuilder(
                kekDeriver, keyWrap
        );
        RecordingGcmCrypto recordingGcm = new RecordingGcmCrypto(realGcm);
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                recipientBuilder, recordingGcm, random
        );
        ProtocolPayload payload = payload();
        byte[] senderPrivate = filled(32, 0x11);
        byte[] firstPrivate = filled(32, 0x22);
        byte[] secondPrivate = filled(32, 0x33);

        try (X25519PrivateKeyHandle senderKey = x25519.importPrivateKey(senderPrivate);
             X25519PrivateKeyHandle first = x25519.importPrivateKey(firstPrivate);
             X25519PrivateKeyHandle second = x25519.importPrivateKey(secondPrivate)) {
            byte[] senderPublic = senderKey.publicKey();
            byte[] firstPublic = first.publicKey();
            byte[] secondPublic = second.publicKey();
            PublicX25519UnsignedSender.Result result = sender.send(
                    new PublicX25519UnsignedSender.Request(
                            payload,
                            MESSAGE_ID,
                            TIMESTAMP,
                            senderKey,
                            List.of(firstPublic, secondPublic)
                    )
            );

            WindLetter parsed = new JacksonOuterWireParser().parse(result.wireJson());
            assertEquals(1, recordingGcm.encryptCalls);
            assertEquals(1, occurrences(result.wireJson(), "\"ciphertext\""));
            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+inner", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("public", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519", parsed.protectedHeader().keyAlg());
            SenderKid senderKid = assertInstanceOf(SenderKid.class, parsed.protectedHeader().senderInfo());
            assertEquals(X25519KeyId.derive(senderPublic), senderKid.x25519());
            assertEquals(
                    Base64Url.encode(JcsCanonicalizer.canonicalize(
                            OuterJsonMapper.toProtectedJson(parsed.protectedHeader())
                    )),
                    parsed.protectedValue()
            );

            assertEquals(2, parsed.recipients().size());
            PublicRecipient firstRecipient = publicRecipient(parsed.recipients().get(0));
            PublicRecipient secondRecipient = publicRecipient(parsed.recipients().get(1));
            assertEquals(X25519KeyId.derive(firstPublic), firstRecipient.kid().x25519());
            assertEquals(X25519KeyId.derive(secondPublic), secondRecipient.kid().x25519());
            assertEquals(40, firstRecipient.encryptedKey().length);
            assertEquals(40, secondRecipient.encryptedKey().length);
            assertFalse(Arrays.equals(firstRecipient.encryptedKey(), secondRecipient.encryptedKey()));
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());

            UnsignedInnerCodec.Message firstInner = decryptFor(
                    first, firstRecipient, senderPublic, parsed, kekDeriver, keyWrap, realGcm
            );
            UnsignedInnerCodec.Message secondInner = decryptFor(
                    second, secondRecipient, senderPublic, parsed, kekDeriver, keyWrap, realGcm
            );
            assertInner(firstInner, payload, parsed);
            assertInner(secondInner, payload, parsed);
            assertEquals(firstInner.messageId(), secondInner.messageId());
            assertWrappedCekEquals(
                    random.snapshots.get(0), first, firstRecipient, senderPublic, kekDeriver, keyWrap
            );
            assertWrappedCekEquals(
                    random.snapshots.get(0), second, secondRecipient, senderPublic, kekDeriver, keyWrap
            );

            assertSecretsAbsent(
                    result.wireJson(),
                    senderPrivate,
                    firstPrivate,
                    secondPrivate,
                    random.snapshots.get(0)
            );
            assertDerivedSecretsAbsent(
                    result.wireJson(), senderKey, List.of(firstPublic, secondPublic), x25519, hkdf
            );
            assertEquals(32, senderKey.publicKey().length);
            assertArrayEquals(parsed.iv(), result.message().iv());
            assertArrayEquals(parsed.ciphertext(), result.message().ciphertext());
            assertArrayEquals(parsed.tag(), result.message().tag());
            assertTrue(random.references.stream().allMatch(PublicX25519UnsignedSenderTest::allZero));
            assertTrue(recordingGcm.capturedReferences().stream()
                    .allMatch(PublicX25519UnsignedSenderTest::allZero));
        }
    }

    @Test
    void consecutiveEquivalentSendsUseFreshCekAndIvAndOneCiphertextEach() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        SequenceSecureRandom random = new SequenceSecureRandom();
        PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                realRecipientBuilder(x25519), gcm, random
        );
        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            PublicX25519UnsignedSender.Request request = new PublicX25519UnsignedSender.Request(
                    payload(), MESSAGE_ID, TIMESTAMP, senderKey, List.of(recipient.publicKey())
            );

            PublicX25519UnsignedSender.Result first = sender.send(request);
            PublicX25519UnsignedSender.Result second = sender.send(request);

            assertEquals(2, gcm.encryptCalls);
            assertFalse(Arrays.equals(first.message().iv(), second.message().iv()));
            assertFalse(Arrays.equals(first.message().ciphertext(), second.message().ciphertext()));
            assertNotEquals(first.wireJson(), second.wireJson());
            assertArrayEquals(random.snapshots.get(1), first.message().iv());
            assertArrayEquals(random.snapshots.get(3), second.message().iv());
            assertTrue(random.references.stream().allMatch(PublicX25519UnsignedSenderTest::allZero));
            assertEquals(32, senderKey.publicKey().length);
        }
    }

    @Test
    void lowOrderRecipientFailureClearsGeneratedSecretsAndLeavesBorrowedHandleOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        RecordingGcmCrypto gcm = new RecordingGcmCrypto(new BouncyCastleA256GcmCrypto());
        PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                realRecipientBuilder(x25519), gcm, random
        );
        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class, () -> sender.send(
                    new PublicX25519UnsignedSender.Request(
                            payload(), MESSAGE_ID, TIMESTAMP, senderKey, List.of(new byte[32])
                    )
            ));

            assertEquals(0, gcm.encryptCalls);
            assertEquals(2, random.references.size());
            assertTrue(random.references.stream().allMatch(PublicX25519UnsignedSenderTest::allZero));
            assertEquals(32, senderKey.publicKey().length);
        }
    }

    @Test
    void gcmFailureClearsCekIvAadAndInnerAndLeavesBorrowedHandleOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        SequenceSecureRandom random = new SequenceSecureRandom();
        FailingGcmCrypto gcm = new FailingGcmCrypto();
        PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                realRecipientBuilder(x25519), gcm, random
        );
        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            byte[] callerRecipientKey = recipient.publicKey();
            byte[] expectedRecipientKey = callerRecipientKey.clone();

            assertThrows(CryptoOperationException.class, () -> sender.send(
                    new PublicX25519UnsignedSender.Request(
                            payload(), MESSAGE_ID, TIMESTAMP, senderKey, List.of(callerRecipientKey)
                    )
            ));

            assertEquals(1, gcm.encryptCalls);
            assertTrue(gcm.capturedReferences().stream()
                    .allMatch(PublicX25519UnsignedSenderTest::allZero));
            assertTrue(random.references.stream().allMatch(PublicX25519UnsignedSenderTest::allZero));
            assertArrayEquals(expectedRecipientKey, callerRecipientKey);
            assertEquals(32, senderKey.publicKey().length);
        }
    }

    @Test
    void requestValidatesProtocolBoundsAndDeepSnapshotsRecipientKeys() {
        ProtocolPayload payload = payload();
        X25519PrivateKeyHandle handle = dummyHandle();
        byte[] key = filled(32, 1);

        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(null, MESSAGE_ID, TIMESTAMP, handle, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(payload, null, TIMESTAMP, handle, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, "123E4567-E89B-42D3-A456-426614174000", TIMESTAMP, handle, List.of(key)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP, handle, List.of(key)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, "123e4567-e89b-42d3-7456-426614174000", TIMESTAMP, handle, List.of(key)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(payload, MESSAGE_ID, -1, handle, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER + 1, handle, List.of(key)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(payload, MESSAGE_ID, TIMESTAMP, null, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(payload, MESSAGE_ID, TIMESTAMP, handle, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(payload, MESSAGE_ID, TIMESTAMP, handle, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, handle, uniqueKeys(33)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, handle, Arrays.asList((byte[]) null)
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, handle, List.of(new byte[31])
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, handle, List.of(new byte[33])
                ));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, handle, List.of(key, key.clone())
                ));

        ArrayList<byte[]> callerList = new ArrayList<>();
        byte[] callerKey = filled(32, 0x55);
        byte[] expected = callerKey.clone();
        callerList.add(callerKey);
        PublicX25519UnsignedSender.Request snapshot = new PublicX25519UnsignedSender.Request(
                payload, MESSAGE_ID, MAX_SAFE_JSON_INTEGER, handle, callerList
        );
        Arrays.fill(callerKey, (byte) 0);
        callerList.clear();
        assertEquals(1, snapshot.recipientPublicKeys().size());
        assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
        byte[] accessorValue = snapshot.recipientPublicKeys().get(0);
        Arrays.fill(accessorValue, (byte) 0);
        assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
        assertEquals(32, new PublicX25519UnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, handle, uniqueKeys(32)
        ).recipientPublicKeys().size());
    }

    @Test
    void validatesConstructorDependencies() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519RecipientBuilder builder = realRecipientBuilder(x25519);
        A256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();

        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender(null, gcm));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender(builder, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519UnsignedSender(builder, gcm, null));
        assertNotNull(new PublicX25519UnsignedSender(builder, gcm));
    }

    private static PublicX25519RecipientBuilder realRecipientBuilder(BouncyCastleX25519Crypto x25519) {
        return new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                new BouncyCastleA256KeyWrapCrypto()
        );
    }

    private static UnsignedInnerCodec.Message decryptFor(
            X25519PrivateKeyHandle recipientKey,
            PublicRecipient recipient,
            byte[] senderPublic,
            WindLetter letter,
            PublicX25519KekDeriver deriver,
            BouncyCastleA256KeyWrapCrypto keyWrap,
            BouncyCastleA256GcmCrypto gcm
    ) {
        byte[] cek = unwrapCek(recipientKey, recipient, senderPublic, deriver, keyWrap);
        byte[] plaintext = null;
        try {
            plaintext = gcm.decrypt(
                    cek,
                    letter.iv(),
                    new OuterAad().gcmInput(letter.protectedValue(), letter.aad()),
                    letter.ciphertext(),
                    letter.tag()
            );
            return new UnsignedInnerCodec().decode(plaintext);
        } finally {
            Arrays.fill(cek, (byte) 0);
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private static byte[] unwrapCek(
            X25519PrivateKeyHandle recipientKey,
            PublicRecipient recipient,
            byte[] senderPublic,
            PublicX25519KekDeriver deriver,
            BouncyCastleA256KeyWrapCrypto keyWrap
    ) {
        byte[] kek = deriver.derive(recipientKey, senderPublic);
        try {
            return keyWrap.unwrap(kek, recipient.encryptedKey());
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    private static void assertInner(
            UnsignedInnerCodec.Message inner,
            ProtocolPayload expectedPayload,
            WindLetter parsed
    ) {
        assertEquals(MESSAGE_ID, inner.messageId());
        assertEquals(TIMESTAMP, inner.timestamp());
        assertEquals(expectedPayload.contentType(), inner.payload().contentType());
        assertEquals(expectedPayload.originalSize(), inner.payload().originalSize());
        assertArrayEquals(expectedPayload.data(), inner.payload().data());
        new OuterBinding().verify(inner.binding(), parsed.protectedHeader(), parsed.recipients());
    }

    private static PublicRecipient publicRecipient(RecipientEntry entry) {
        PublicRecipient recipient = assertInstanceOf(PublicRecipient.class, entry);
        assertNull(recipient.ek());
        assertNull(recipient.kid().mlkem768());
        return recipient;
    }

    private static void assertWrappedCekEquals(
            byte[] expected,
            X25519PrivateKeyHandle recipientKey,
            PublicRecipient recipient,
            byte[] senderPublic,
            PublicX25519KekDeriver deriver,
            BouncyCastleA256KeyWrapCrypto keyWrap
    ) {
        byte[] actual = unwrapCek(recipientKey, recipient, senderPublic, deriver, keyWrap);
        try {
            assertArrayEquals(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static void assertDerivedSecretsAbsent(
            String wireJson,
            X25519PrivateKeyHandle senderKey,
            List<byte[]> recipientPublicKeys,
            BouncyCastleX25519Crypto x25519,
            BouncyCastleHkdfCrypto hkdf
    ) {
        for (byte[] recipientPublicKey : recipientPublicKeys) {
            byte[] shared = x25519.deriveSharedSecret(senderKey, recipientPublicKey);
            byte[] kek = hkdf.derive(
                    "wind".getBytes(StandardCharsets.UTF_8),
                    shared,
                    "WindLetter v1 KEK | X25519".getBytes(StandardCharsets.UTF_8),
                    32
            );
            try {
                assertSecretsAbsent(wireJson, shared, kek);
            } finally {
                Arrays.fill(shared, (byte) 0);
                Arrays.fill(kek, (byte) 0);
            }
        }
    }

    private static void assertSecretsAbsent(String wireJson, byte[]... secrets) {
        for (byte[] secret : secrets) {
            assertFalse(wireJson.contains(Base64Url.encode(secret)));
            assertFalse(wireJson.toLowerCase().contains(HexFormat.of().formatHex(secret)));
        }
    }

    private static ProtocolPayload payload() {
        return new ProtocolPayload("application/octet-stream", PAYLOAD_BYTES, PAYLOAD_BYTES.length);
    }

    private static X25519PrivateKeyHandle dummyHandle() {
        return new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return filled(32, 0x7f);
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

    private static int occurrences(String text, String value) {
        int count = 0;
        int from = 0;
        while ((from = text.indexOf(value, from)) >= 0) {
            count++;
            from += value.length();
        }
        return count;
    }

    private static byte[] filled(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
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
        protected int encryptCalls;
        protected byte[] key;
        protected byte[] iv;
        protected byte[] aad;
        protected byte[] plaintext;

        private RecordingGcmCrypto(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            capture(key, iv, aad, plaintext);
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
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

    private static final class FailingGcmCrypto extends RecordingGcmCrypto {
        private FailingGcmCrypto() {
            super(new BouncyCastleA256GcmCrypto());
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            capture(key, iv, aad, plaintext);
            throw new CryptoOperationException("intentional GCM failure");
        }
    }
}
