package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519SignedSenderTest {

    @Test
    void signsActualKidAndEncryptsExactFinalObfuscationProfileWhileClearingOwnedArrays() {
        try (Fixture fixture = new Fixture()) {
            TrackingEd25519 signer = new TrackingEd25519(
                    fixture.ed25519, fixture.senderSigning, SignMode.DELEGATE
            );
            CapturingSigningHandle signingHandle = new CapturingSigningHandle(
                    fixture.senderSigning, PublicMode.DELEGATE
            );
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, false);
            TrackingRandom random = new TrackingRandom();
            ObfuscationX25519SignedSender sender = new ObfuscationX25519SignedSender(
                    fixture.builder(), gcm, signer, random
            );

            ObfuscationX25519SignedSender.Result result = sender.send(
                    new ObfuscationX25519SignedSender.Request(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, signingHandle,
                            List.of(fixture.first.publicKey(), fixture.second.publicKey(),
                                    fixture.third.publicKey())
                    )
            );
            WindLetter parsed = new JacksonOuterWireParser().parse(result.wireJson());

            assertEquals("wind+jwe", parsed.protectedHeader().typ());
            assertEquals("wind+jws", parsed.protectedHeader().cty());
            assertEquals("1.0", parsed.protectedHeader().ver());
            assertEquals("obfuscation", parsed.protectedHeader().windMode());
            assertEquals("A256GCM", parsed.protectedHeader().enc());
            assertEquals("X25519", parsed.protectedHeader().keyAlg());
            Epk epk = assertInstanceOf(Epk.class, parsed.protectedHeader().senderInfo());
            assertEquals(32, epk.x().length);
            assertEquals(8, parsed.recipients().size());
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
            assertEquals(Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(parsed.protectedHeader())
            )), parsed.protectedValue());
            assertArrayEquals(new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad()),
                    gcm.aadSnapshot);

            byte[] actualPublic = fixture.senderSigning.publicKey();
            try (SignedInnerCodec.Decoded decoded = new SignedInnerCodec().decode(gcm.plaintextSnapshot)) {
                assertEquals(Ed25519KeyId.derive(actualPublic), decoded.message().signingKid());
                assertArrayEquals(signer.messageSnapshot, decoded.signingInput());
                assertArrayEquals(signer.signatureSnapshot, decoded.signature());
                OuterBinding.Hashes expected = new OuterBinding().compute(
                        parsed.protectedHeader(), parsed.recipients()
                );
                assertArrayEquals(expected.protectedHash(),
                        decoded.message().binding().protectedHash());
                assertArrayEquals(expected.recipientsHash(),
                        decoded.message().binding().recipientsHash());
            } finally {
                clear(actualPublic);
            }
            assertEquals(result.wireJson(),
                    new com.windletter.protocol.codec.JacksonOuterWireWriter().write(result.message()));
            assertEquals(0, signingHandle.closeCalls);
            assertTrue(signingHandle.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(random.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(signer.rawReferences().stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(gcm.rawReferences().stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
        }
    }

    @Test
    void requestPrevalidatesAndDeepSnapshotsRecipientsWithoutOwningSigningHandle() {
        try (Fixture fixture = new Fixture()) {
            ProtocolPayload payload = fixture.emptyPayload();
            byte[] key = filled(32, 1);
            assertThrows(IllegalArgumentException.class, () -> request(null, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, null,
                    TIMESTAMP, fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload,
                    MESSAGE_ID.toUpperCase(), TIMESTAMP, fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload,
                    "123e4567-e89b-12d3-a456-426614174000", TIMESTAMP,
                    fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    -1, fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    9_007_199_254_740_992L, fixture.senderSigning, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, null, List.of(key)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, null));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, List.of()));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, Arrays.asList((byte[]) null)));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, List.of(new byte[31])));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, List.of(key, key.clone())));
            assertThrows(IllegalArgumentException.class, () -> request(payload, MESSAGE_ID,
                    TIMESTAMP, fixture.senderSigning, uniqueKeys(33)));

            byte[] expected = key.clone();
            ArrayList<byte[]> callerList = new ArrayList<>(List.of(key));
            ObfuscationX25519SignedSender.Request snapshot = request(
                    payload, MESSAGE_ID, 9_007_199_254_740_991L,
                    fixture.senderSigning, callerList
            );
            callerList.clear();
            Arrays.fill(key, (byte) 0);
            assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
            byte[] accessor = snapshot.recipientPublicKeys().get(0);
            Arrays.fill(accessor, (byte) 0);
            assertArrayEquals(expected, snapshot.recipientPublicKeys().get(0));
            assertSame(fixture.senderSigning, snapshot.senderSigningPrivateKey());
            assertEquals(32, request(payload, MESSAGE_ID, TIMESTAMP,
                    fixture.senderSigning, uniqueKeys(32)).recipientPublicKeys().size());
        }
    }

    @Test
    void signingPublicKeyAndSignatureProviderFailuresAreRejectedAndClearEveryAvailableArray() {
        try (Fixture fixture = new Fixture()) {
            for (PublicMode mode : List.of(PublicMode.NULL, PublicMode.WRONG_LENGTH,
                    PublicMode.THROW)) {
                CapturingSigningHandle handle = new CapturingSigningHandle(
                        fixture.senderSigning, mode
                );
                TrackingEd25519 signer = new TrackingEd25519(
                        fixture.ed25519, fixture.senderSigning, SignMode.DELEGATE
                );
                TrackingRandom random = new TrackingRandom();
                assertThrows(RuntimeException.class, () -> new ObfuscationX25519SignedSender(
                        fixture.builder(), fixture.gcm, signer, random
                ).send(request(fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, handle,
                        List.of(fixture.first.publicKey()))));
                assertEquals(0, signer.signCalls);
                assertTrue(handle.references.stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
                assertTrue(random.references.stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
                assertEquals(0, handle.closeCalls);
            }

            for (SignMode mode : List.of(SignMode.THROW, SignMode.NULL,
                    SignMode.WRONG_LENGTH)) {
                TrackingEd25519 signer = new TrackingEd25519(
                        fixture.ed25519, fixture.senderSigning, mode
                );
                CapturingSigningHandle handle = new CapturingSigningHandle(
                        fixture.senderSigning, PublicMode.DELEGATE
                );
                TrackingRandom random = new TrackingRandom();
                assertThrows(RuntimeException.class, () -> new ObfuscationX25519SignedSender(
                        fixture.builder(), fixture.gcm, signer, random
                ).send(request(fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, handle,
                        List.of(fixture.first.publicKey()))));
                assertEquals(1, signer.signCalls);
                assertTrue(signer.rawReferences().stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
                assertTrue(handle.references.stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
                assertTrue(random.references.stream().allMatch(
                        ObfuscationX25519FlowTestFixtures::allZero));
                assertEquals(0, handle.closeCalls);
            }
        }
    }

    @Test
    void gcmAfterSigningFailureClearsSignatureInnerCekIvAndAadAndValidatesDependencies() {
        try (Fixture fixture = new Fixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender(null, fixture.gcm, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender(fixture.builder(), null, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender(fixture.builder(), fixture.gcm, null));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender(
                            fixture.builder(), fixture.gcm, fixture.ed25519, null));

            TrackingEd25519 signer = new TrackingEd25519(
                    fixture.ed25519, fixture.senderSigning, SignMode.DELEGATE
            );
            CapturingSigningHandle handle = new CapturingSigningHandle(
                    fixture.senderSigning, PublicMode.DELEGATE
            );
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, true);
            TrackingRandom random = new TrackingRandom();
            assertThrows(CryptoOperationException.class, () ->
                    new ObfuscationX25519SignedSender(
                            fixture.builder(), gcm, signer, random
                    ).send(request(fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, handle,
                            List.of(fixture.first.publicKey()))));
            assertEquals(1, signer.signCalls);
            assertEquals(1, gcm.encryptCalls);
            assertTrue(signer.rawReferences().stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(handle.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(random.references.stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertTrue(gcm.rawReferences().stream().allMatch(
                    ObfuscationX25519FlowTestFixtures::allZero));
            assertEquals(0, handle.closeCalls);

            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender.Result(null, "{}"));
            WindLetter message = new JacksonOuterWireParser().parse(
                    fixture.sendSigned(fixture.emptyPayload())
            );
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedSender.Result(message, " "));
        }
    }

    private static ObfuscationX25519SignedSender.Request request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            Ed25519PrivateKeyHandle signingKey,
            List<byte[]> recipients
    ) {
        return new ObfuscationX25519SignedSender.Request(
                payload, messageId, timestamp, signingKey, recipients
        );
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

    private enum SignMode { DELEGATE, THROW, NULL, WRONG_LENGTH }

    private enum PublicMode { DELEGATE, THROW, NULL, WRONG_LENGTH }

    private static final class CapturingSigningHandle implements Ed25519PrivateKeyHandle {
        private final Ed25519PrivateKeyHandle delegate;
        private final PublicMode mode;
        private final List<byte[]> references = new ArrayList<>();
        private int closeCalls;

        private CapturingSigningHandle(Ed25519PrivateKeyHandle delegate, PublicMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override
        public byte[] publicKey() {
            if (mode == PublicMode.THROW) throw new IllegalStateException("closed");
            byte[] result = mode == PublicMode.NULL ? null
                    : mode == PublicMode.WRONG_LENGTH ? filled(31, 0x41)
                    : delegate.publicKey();
            if (result != null) references.add(result);
            return result;
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class TrackingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final Ed25519PrivateKeyHandle delegateHandle;
        private final SignMode mode;
        private int signCalls;
        private byte[] message;
        private byte[] signature;
        private byte[] messageSnapshot;
        private byte[] signatureSnapshot;

        private TrackingEd25519(
                Ed25519Crypto delegate,
                Ed25519PrivateKeyHandle delegateHandle,
                SignMode mode
        ) {
            this.delegate = delegate;
            this.delegateHandle = delegateHandle;
            this.mode = mode;
        }

        @Override public Ed25519PrivateKeyHandle generatePrivateKey() { return delegate.generatePrivateKey(); }
        @Override public Ed25519PrivateKeyHandle importPrivateKey(byte[] key) {
            return delegate.importPrivateKey(key);
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            signCalls++;
            this.message = message;
            this.messageSnapshot = message.clone();
            if (mode == SignMode.THROW) throw new CryptoOperationException("intentional sign failure");
            signature = mode == SignMode.NULL ? null
                    : mode == SignMode.WRONG_LENGTH ? filled(63, 0x31)
                    : delegate.sign(delegateHandle, message);
            if (signature != null) signatureSnapshot = signature.clone();
            return signature;
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return delegate.verify(publicKey, message, signature);
        }

        private List<byte[]> rawReferences() {
            ArrayList<byte[]> result = new ArrayList<>();
            if (message != null) result.add(message);
            if (signature != null) result.add(signature);
            return result;
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final boolean fail;
        private int encryptCalls;
        private byte[] key;
        private byte[] iv;
        private byte[] aad;
        private byte[] plaintext;
        private byte[] aadSnapshot;
        private byte[] plaintextSnapshot;

        private RecordingGcm(A256GcmCrypto delegate, boolean fail) {
            this.delegate = delegate;
            this.fail = fail;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            encryptCalls++;
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
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
        }

        private List<byte[]> rawReferences() {
            return List.of(key, iv, aad, plaintext);
        }
    }
}
