package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
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

class ObfuscationHybridUnsignedSenderTest {

    @Test
    void emitsExactHybridProfileAndAuthenticatesTheFinalShuffledBucket() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            TrackingRandom random = new TrackingRandom();
            ObfuscationHybridUnsignedSender sender =
                    new ObfuscationHybridUnsignedSender(
                            fixture.builder(), gcm, random
                    );

            ObfuscationHybridUnsignedSender.Result result = sender.send(
                    new ObfuscationHybridUnsignedSender.Request(
                            fixture.binaryPayload(),
                            ProtocolFlowTestFixtures.MESSAGE_ID,
                            ProtocolFlowTestFixtures.TIMESTAMP,
                            fixture.recipients().stream()
                                    .map(ObfuscationHybridFlowTestFixtures.HybridPair::publicKeys)
                                    .toList()
                    )
            );
            WindLetter parsed = new JacksonOuterWireParser().parse(result.wireJson());

            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+inner", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("obfuscation", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519ML-KEM-768", parsed.protectedHeader().keyAlg());
            Epk epk = assertInstanceOf(
                    Epk.class, parsed.protectedHeader().senderInfo()
            );
            assertEquals("OKP", epk.kty());
            assertEquals("X25519", epk.crv());
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
            assertEquals(Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(parsed.protectedHeader())
            )), parsed.protectedValue());
            assertArrayEquals(
                    new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad()),
                    gcm.aadSnapshot
            );
            UnsignedInnerCodec.Message inner =
                    new UnsignedInnerCodec().decode(gcm.plaintextSnapshot);
            OuterBinding.Hashes expectedBinding = new OuterBinding().compute(
                    parsed.protectedHeader(), parsed.recipients()
            );
            assertArrayEquals(
                    expectedBinding.protectedHash(), inner.binding().protectedHash()
            );
            assertArrayEquals(
                    expectedBinding.recipientsHash(), inner.binding().recipientsHash()
            );
            assertArrayEquals(
                    ProtocolFlowTestFixtures.BINARY_PAYLOAD, inner.payload().data()
            );
            assertEquals(2, random.references.size());
            assertEquals(4, gcm.rawReferences().size());
            assertTrue(random.references.stream().allMatch(
                    ObfuscationHybridUnsignedSenderTest::allZero
            ));
            assertTrue(gcm.rawReferences().stream().allMatch(
                    ObfuscationHybridUnsignedSenderTest::allZero
            ));
            ObfuscationHybridFlowTestFixtures.clear(gcm.aadSnapshot);
            ObfuscationHybridFlowTestFixtures.clear(gcm.plaintextSnapshot);
        }
    }

    @Test
    void clearsOwnedSenderArraysWhenGcmFails() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, true);
            TrackingRandom random = new TrackingRandom();
            ObfuscationHybridUnsignedSender sender =
                    new ObfuscationHybridUnsignedSender(
                            fixture.builder(), gcm, random
                    );

            assertThrows(CryptoOperationException.class, () -> sender.send(
                    new ObfuscationHybridUnsignedSender.Request(
                            fixture.binaryPayload(),
                            ProtocolFlowTestFixtures.MESSAGE_ID,
                            ProtocolFlowTestFixtures.TIMESTAMP,
                            List.of(fixture.first.publicKeys())
                    )
            ));

            assertEquals(2, random.references.size());
            assertEquals(4, gcm.rawReferences().size());
            assertTrue(random.references.stream().allMatch(
                    ObfuscationHybridUnsignedSenderTest::allZero
            ));
            assertTrue(gcm.rawReferences().stream().allMatch(
                    ObfuscationHybridUnsignedSenderTest::allZero
            ));
            ObfuscationHybridFlowTestFixtures.clear(gcm.aadSnapshot);
            ObfuscationHybridFlowTestFixtures.clear(gcm.plaintextSnapshot);
        }
    }

    @Test
    void requestSnapshotsPairsRejectsOnlyExactPairDuplicatesAndValidatesBounds() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            ProtocolPayload payload = fixture.binaryPayload();
            ObfuscationHybridRecipientKeys first = fixture.first.publicKeys();
            ObfuscationHybridRecipientKeys middle = fixture.middle.publicKeys();
            byte[] firstX = first.x25519PublicKey();
            byte[] firstPq = first.mlkem768PublicKey();
            byte[] middleX = middle.x25519PublicKey();
            byte[] middlePq = middle.mlkem768PublicKey();
            try {
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridUnsignedSender.Request(
                                null, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP, List.of(first)
                        ));
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridUnsignedSender.Request(
                                payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP, null
                        ));
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridUnsignedSender.Request(
                                payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP, List.of()
                        ));
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridUnsignedSender.Request(
                                payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP,
                                Arrays.asList((ObfuscationHybridRecipientKeys) null)
                        ));
                assertThrows(IllegalArgumentException.class, () ->
                        new ObfuscationHybridUnsignedSender.Request(
                                payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP,
                                List.of(first, new ObfuscationHybridRecipientKeys(
                                        firstX, firstPq))
                        ));

                assertDoesNotThrow(() -> new ObfuscationHybridUnsignedSender.Request(
                        payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                        ProtocolFlowTestFixtures.TIMESTAMP,
                        List.of(
                                new ObfuscationHybridRecipientKeys(firstX, firstPq),
                                new ObfuscationHybridRecipientKeys(firstX, middlePq),
                                new ObfuscationHybridRecipientKeys(middleX, firstPq)
                        )
                ));

                ArrayList<ObfuscationHybridRecipientKeys> caller =
                        new ArrayList<>(List.of(first));
                ObfuscationHybridUnsignedSender.Request request =
                        new ObfuscationHybridUnsignedSender.Request(
                                payload, ProtocolFlowTestFixtures.MESSAGE_ID,
                                ProtocolFlowTestFixtures.TIMESTAMP, caller
                        );
                caller.clear();
                Arrays.fill(firstX, (byte) 0);
                byte[] expectedX25519 = fixture.first.x25519.publicKey();
                byte[] actualX25519 =
                        request.recipients().get(0).x25519PublicKey();
                try {
                    assertArrayEquals(expectedX25519, actualX25519);
                } finally {
                    ObfuscationHybridFlowTestFixtures.clear(expectedX25519);
                    ObfuscationHybridFlowTestFixtures.clear(actualX25519);
                }
                assertThrows(UnsupportedOperationException.class,
                        () -> request.recipients().add(middle));
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(firstX);
                ObfuscationHybridFlowTestFixtures.clear(firstPq);
                ObfuscationHybridFlowTestFixtures.clear(middleX);
                ObfuscationHybridFlowTestFixtures.clear(middlePq);
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
        private final boolean fail;
        private byte[] key;
        private byte[] iv;
        private byte[] aad;
        private byte[] plaintext;
        private byte[] aadSnapshot;
        private byte[] plaintextSnapshot;

        private RecordingGcm(A256GcmCrypto delegate) {
            this(delegate, false);
        }

        private RecordingGcm(A256GcmCrypto delegate, boolean fail) {
            this.delegate = delegate;
            this.fail = fail;
        }

        @Override
        public AeadCiphertext encrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] plaintext
        ) {
            this.key = key;
            this.iv = iv;
            this.aad = aad;
            this.plaintext = plaintext;
            aadSnapshot = aad.clone();
            plaintextSnapshot = plaintext.clone();
            if (fail) throw new CryptoOperationException("intentional GCM failure");
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
