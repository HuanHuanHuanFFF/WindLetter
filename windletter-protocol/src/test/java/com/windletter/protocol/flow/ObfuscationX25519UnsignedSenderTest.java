package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.MESSAGE_ID;
import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.TIMESTAMP;
import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.allZero;
import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.filled;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519UnsignedSenderTest {

    @Test
    void sendsExactObfuscationProfileAndAuthenticatesFinalPaddedRecipients() {
        try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                     new ObfuscationX25519FlowTestFixtures.Fixture()) {
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, Mode.DELEGATE);
            ObfuscationX25519FlowTestFixtures.TrackingRandom random =
                    new ObfuscationX25519FlowTestFixtures.TrackingRandom();
            ObfuscationX25519UnsignedSender sender = new ObfuscationX25519UnsignedSender(
                    fixture.builder(), gcm, random
            );
            byte[] first = fixture.first.publicKey();
            byte[] second = fixture.second.publicKey();
            byte[] third = fixture.third.publicKey();
            byte[] firstBefore = first.clone();

            ObfuscationX25519UnsignedSender.Result result = sender.send(
                    new ObfuscationX25519UnsignedSender.Request(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP,
                            List.of(first, second, third)
                    )
            );
            WindLetter parsed = new JacksonOuterWireParser().parse(result.wireJson());

            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+inner", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("obfuscation", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519", parsed.protectedHeader().keyAlg());
            Epk epk = assertInstanceOf(Epk.class, parsed.protectedHeader().senderInfo());
            assertEquals("OKP", epk.kty());
            assertEquals("X25519", epk.crv());
            assertEquals(32, epk.x().length);
            assertEquals(8, parsed.recipients().size());
            parsed.recipients().forEach(entry -> {
                ObfuscationRecipient recipient = assertInstanceOf(ObfuscationRecipient.class, entry);
                assertEquals(16, recipient.rid().length);
                assertEquals(40, recipient.encryptedKey().length);
                assertNull(recipient.ek());
            });
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
            assertEquals(Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(parsed.protectedHeader())
            )), parsed.protectedValue());
            assertArrayEquals(
                    new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad()), gcm.aadSnapshot
            );
            UnsignedInnerCodec.Message inner = new UnsignedInnerCodec().decode(gcm.plaintextSnapshot);
            OuterBinding.Hashes binding = new OuterBinding().compute(
                    parsed.protectedHeader(), parsed.recipients()
            );
            assertArrayEquals(binding.protectedHash(), inner.binding().protectedHash());
            assertArrayEquals(binding.recipientsHash(), inner.binding().recipientsHash());
            assertArrayEquals(fixture.binaryPayload().data(), inner.payload().data());
            assertArrayEquals(firstBefore, first);
            assertEquals(result.wireJson(), new com.windletter.protocol.codec.JacksonOuterWireWriter()
                    .write(result.message()));
            assertTrue(random.references.stream().allMatch(ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(gcm.references().stream().allMatch(ObfuscationX25519FlowTestFixtures::allZero));
        }
    }

    @Test
    void requestStrictlyPrevalidatesAndDeepSnapshotsRecipientKeys() {
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", new byte[0], 0);
        byte[] key = filled(32, 1);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(null, MESSAGE_ID, TIMESTAMP, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(payload, null, TIMESTAMP, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID.toUpperCase(), TIMESTAMP, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(payload, MESSAGE_ID, -1, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, 9_007_199_254_740_992L, List.of(key)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(payload, MESSAGE_ID, TIMESTAMP, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(payload, MESSAGE_ID, TIMESTAMP, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, Arrays.asList((byte[]) null)));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, List.of(new byte[31])));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, List.of(key, key.clone())));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, uniqueKeys(33)));

        byte[] expected = key.clone();
        ArrayList<byte[]> callerList = new ArrayList<>(List.of(key));
        ObfuscationX25519UnsignedSender.Request request =
                new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, 9_007_199_254_740_991L, callerList);
        callerList.clear();
        Arrays.fill(key, (byte) 0);
        assertArrayEquals(expected, request.recipientPublicKeys().get(0));
        byte[] accessor = request.recipientPublicKeys().get(0);
        Arrays.fill(accessor, (byte) 0);
        assertArrayEquals(expected, request.recipientPublicKeys().get(0));
        assertEquals(32, new ObfuscationX25519UnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, uniqueKeys(32)).recipientPublicKeys().size());
    }

    @Test
    void prevalidationBuilderFailureAndGcmFailureRespectGateOrderAndClearOwnedArrays() {
        try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                     new ObfuscationX25519FlowTestFixtures.Fixture()) {
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, Mode.FAIL);
            ObfuscationX25519FlowTestFixtures.TrackingRandom prevalidationRandom =
                    new ObfuscationX25519FlowTestFixtures.TrackingRandom();
            ObfuscationX25519UnsignedSender prevalidationSender =
                    new ObfuscationX25519UnsignedSender(fixture.builder(), gcm, prevalidationRandom);
            assertThrows(IllegalArgumentException.class, () -> prevalidationSender.send(null));
            assertTrue(prevalidationRandom.references.isEmpty());
            assertEquals(0, gcm.encryptCalls);

            ObfuscationX25519FlowTestFixtures.TrackingRandom builderRandom =
                    new ObfuscationX25519FlowTestFixtures.TrackingRandom();
            ObfuscationX25519UnsignedSender builderFailure =
                    new ObfuscationX25519UnsignedSender(fixture.builder(), gcm, builderRandom);
            assertThrows(CryptoOperationException.class, () -> builderFailure.send(
                    new ObfuscationX25519UnsignedSender.Request(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, List.of(new byte[32]))
            ));
            assertEquals(0, gcm.encryptCalls);
            assertEquals(2, builderRandom.references.size());
            assertTrue(builderRandom.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));

            ObfuscationX25519FlowTestFixtures.TrackingRandom gcmRandom =
                    new ObfuscationX25519FlowTestFixtures.TrackingRandom();
            ObfuscationX25519UnsignedSender gcmFailure =
                    new ObfuscationX25519UnsignedSender(fixture.builder(), gcm, gcmRandom);
            assertThrows(CryptoOperationException.class, () -> gcmFailure.send(
                    new ObfuscationX25519UnsignedSender.Request(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP,
                            List.of(fixture.first.publicKey())
            )));
            assertEquals(1, gcm.encryptCalls);
            assertTrue(gcm.references().stream().allMatch(ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(gcmRandom.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertEquals(32, fixture.first.publicKey().length);
        }
    }

    @Test
    void rejectsNullOrMalformedGcmProviderOutputAndValidatesDependencies() {
        try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                     new ObfuscationX25519FlowTestFixtures.Fixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedSender(null, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedSender(fixture.builder(), null));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedSender(fixture.builder(), fixture.gcm, null));

            for (Mode mode : List.of(Mode.NULL, Mode.WRONG_LENGTH)) {
                RecordingGcm gcm = new RecordingGcm(fixture.gcm, mode);
                assertThrows(IllegalStateException.class, () ->
                        new ObfuscationX25519UnsignedSender(fixture.builder(), gcm).send(
                                new ObfuscationX25519UnsignedSender.Request(
                                        fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP,
                                        List.of(fixture.first.publicKey())
                                )));
                assertTrue(gcm.references().stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
            }
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedSender.Result(null, "{}"));
            WindLetter message = new JacksonOuterWireParser().parse(fixture.send(fixture.emptyPayload()));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedSender.Result(message, " "));
        }
    }

    private static List<byte[]> uniqueKeys(int count) {
        ArrayList<byte[]> keys = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte[] key = new byte[32];
            key[0] = (byte) i;
            key[31] = (byte) (i + 1);
            keys.add(key);
        }
        return keys;
    }

    private enum Mode { DELEGATE, FAIL, NULL, WRONG_LENGTH }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final Mode mode;
        private int encryptCalls;
        private byte[] key;
        private byte[] iv;
        private byte[] aad;
        private byte[] plaintext;
        private byte[] aadSnapshot;
        private byte[] plaintextSnapshot;

        private RecordingGcm(A256GcmCrypto delegate, Mode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
            this.key = key;
            this.iv = iv;
            this.aad = aad;
            this.plaintext = plaintext;
            this.aadSnapshot = aad.clone();
            this.plaintextSnapshot = plaintext.clone();
            if (mode == Mode.FAIL) throw new CryptoOperationException("intentional GCM failure");
            if (mode == Mode.NULL) return null;
            if (mode == Mode.WRONG_LENGTH) return new AeadCiphertext(new byte[0], new byte[16]);
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
        }

        private List<byte[]> references() {
            return List.of(key, iv, aad, plaintext);
        }
    }
}
