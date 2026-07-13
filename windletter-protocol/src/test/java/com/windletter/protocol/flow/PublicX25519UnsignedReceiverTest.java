package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicX25519UnsignedReceiverTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void receivesRealSenderWireForSecondRecipient() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto());
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                new PublicX25519RecipientBuilder(deriver, keyWrap), gcm
        );
        PublicX25519UnsignedReceiver receiver = new PublicX25519UnsignedReceiver(deriver, keyWrap, gcm);
        byte[] data = {0, 1, 2, (byte) 0xff};
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", data, data.length);
        String messageId = "123e4567-e89b-42d3-a456-426614174000";
        long timestamp = 1_731_800_000L;

        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle first = x25519.generatePrivateKey();
             X25519PrivateKeyHandle second = x25519.generatePrivateKey()) {
            String wire = sender.send(new PublicX25519UnsignedSender.Request(
                    payload, messageId, timestamp, senderKey, List.of(first.publicKey(), second.publicKey())
            )).wireJson();

            PublicX25519UnsignedReceiver.Result result = receiver.receive(
                    new PublicX25519UnsignedReceiver.Request(
                            wire,
                            kid -> java.util.Optional.of(senderKey.publicKey()),
                            List.of(second)
                    )
            );

            assertEquals(messageId, result.messageId());
            assertEquals(timestamp, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.UNSIGNED, result.authenticationStatus());
            assertEquals(payload.contentType(), result.payload().contentType());
            assertArrayEquals(data, result.payload().data());
            assertEquals(32, senderKey.publicKey().length);
            assertEquals(32, second.publicKey().length);
        }
    }

    @Test
    void strictMalformedAndAadMismatchWinBeforeRoutingWhenNoLocalKeyMatches() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger resolverCalls = new AtomicInteger();
            SenderX25519PublicKeyResolver resolver = kid -> {
                resolverCalls.incrementAndGet();
                return Optional.of(fixture.senderKey.publicKey());
            };

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request("{", resolver, List.of(fixture.unrelated))
            ));

            ObjectNode aadTampered = (ObjectNode) JSON.readTree(fixture.wire);
            aadTampered.put("aad", Base64Url.encode(new byte[]{1}));
            assertCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            aadTampered.toString(), resolver, List.of(fixture.unrelated)
                    )
            ));

            assertEquals(0, resolverCalls.get());
            assertEquals(32, fixture.unrelated.publicKey().length);
        }
    }

    @Test
    void validUnrelatedMessageIsNotForMeAndDoesNotResolveSender() {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger resolverCalls = new AtomicInteger();

            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire,
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.senderKey.publicKey());
                            },
                            List.of(fixture.unrelated)
                    )
            ));

            assertEquals(0, resolverCalls.get());
            assertEquals(32, fixture.unrelated.publicKey().length);
        }
    }

    @Test
    void unknownOrWrongSenderPublicKeyIsInvalidAfterRecipientMatch() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.empty(), List.of(fixture.second)
                    )
            ));

            byte[] wrongSender = fixture.unrelated.publicKey();
            byte[] expectedWrongSender = wrongSender.clone();
            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.of(wrongSender), List.of(fixture.second)
                    )
            ));
            assertArrayEquals(expectedWrongSender, wrongSender);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void resolverContractFailuresAreInternalAndNeverNotForMe() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire, kid -> null, List.of(fixture.second)
                    )
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire,
                            kid -> { throw new IllegalStateException("resolver unavailable"); },
                            List.of(fixture.second)
                    )
            ));
            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.of(new byte[31]), List.of(fixture.second)
                    )
            ));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void targetEncryptedKeyTamperWithRecomputedAadIsKeyUnwrapFailure() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            ObjectNode root = (ObjectNode) JSON.readTree(fixture.wire);
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(1);
            byte[] wrapped = Base64Url.decodeCanonical(
                    target.get("encrypted_key").textValue(), "test.encrypted_key"
            );
            wrapped[0] ^= 1;
            target.put("encrypted_key", Base64Url.encode(wrapped));
            root.put("aad", Base64Url.encode(JcsCanonicalizer.canonicalize(root.get("recipients"))));

            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> fixture.receiver().receive(
                    fixture.request(root.toString(), List.of(fixture.second))
            ));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void ivCiphertextAndTagTamperAreGcmFailuresAfterRecipientMatch() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            for (String field : List.of("iv", "ciphertext", "tag")) {
                assertCode(ErrorCode.GCM_AUTH_FAILED, () -> fixture.receiver().receive(
                        fixture.request(tamperTopLevelBytes(fixture.wire, field), List.of(fixture.second))
                ));
                assertEquals(32, fixture.second.publicKey().length);
            }
        }
    }

    @Test
    void validButDifferentOuterProfileIsRejectedBeforeRouting() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            ObjectNode root = (ObjectNode) JSON.readTree(fixture.wire);
            byte[] protectedBytes = Base64Url.decodeCanonical(
                    root.get("protected").textValue(), "test.protected"
            );
            ObjectNode protectedNode = (ObjectNode) JSON.readTree(protectedBytes);
            protectedNode.put("cty", "wind+jws");
            root.put("protected", Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
            AtomicInteger resolverCalls = new AtomicInteger();

            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> fixture.receiver().receive(
                    new PublicX25519UnsignedReceiver.Request(
                            root.toString(),
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.senderKey.publicKey());
                            },
                            List.of(fixture.unrelated)
                    )
            ));
            assertEquals(0, resolverCalls.get());
        }
    }

    @Test
    void authenticatedMalformedInnerPreservesStrictInnerError() {
        try (RealFixture fixture = new RealFixture()) {
            String maliciousWire = fixture.authenticatedWire("{".getBytes(StandardCharsets.UTF_8));

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    fixture.request(maliciousWire, List.of(fixture.second))
            ));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void authenticatedWrongInnerBindingIsBindingFailure() {
        try (RealFixture fixture = new RealFixture()) {
            byte[] maliciousInner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    MESSAGE_ID,
                    TIMESTAMP,
                    fixture.payload,
                    new OuterBinding.Hashes(new byte[32], new byte[32])
            ));
            String maliciousWire = fixture.authenticatedWire(maliciousInner);

            assertCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                    fixture.request(maliciousWire, List.of(fixture.second))
            ));
            assertEquals(32, fixture.second.publicKey().length);
            Arrays.fill(maliciousInner, (byte) 0);
        }
    }

    @Test
    void successClearsKekCekGcmAadAndDecryptedInnerOwnedByReceiver() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            PublicX25519UnsignedReceiver receiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, keyWrap, gcm
            );

            PublicX25519UnsignedReceiver.Result result = receiver.receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            );

            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad, gcm.plaintext);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void unwrapFailureAndMalformedCekClearEveryProviderOutput() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap failing = new RecordingKeyWrap(
                    fixture.keyWrap,
                    new CryptoOperationException("intentional unwrap failure"),
                    null
            );
            PublicX25519UnsignedReceiver failingReceiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, failing, fixture.gcm
            );
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> failingReceiver.receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            ));
            assertAllZero(failing.kek);

            byte[] malformedCek = new byte[31];
            Arrays.fill(malformedCek, (byte) 0x52);
            RecordingKeyWrap malformed = new RecordingKeyWrap(fixture.keyWrap, null, malformedCek);
            PublicX25519UnsignedReceiver malformedReceiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, malformed, fixture.gcm
            );
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> malformedReceiver.receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            ));
            assertAllZero(malformed.kek, malformed.output);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void gcmFailureOrNullOutputClearsKekCekAndAad() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap throwingKeyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm throwingGcm = new RecordingGcm(
                    fixture.gcm,
                    new CryptoOperationException("intentional GCM failure"),
                    false
            );
            PublicX25519UnsignedReceiver throwingReceiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, throwingKeyWrap, throwingGcm
            );
            assertCode(ErrorCode.GCM_AUTH_FAILED, () -> throwingReceiver.receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            ));
            assertAllZero(
                    throwingKeyWrap.kek,
                    throwingKeyWrap.output,
                    throwingGcm.key,
                    throwingGcm.aad
            );

            RecordingKeyWrap nullKeyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm nullGcm = new RecordingGcm(fixture.gcm, null, true);
            PublicX25519UnsignedReceiver nullReceiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, nullKeyWrap, nullGcm
            );
            assertCode(ErrorCode.GCM_AUTH_FAILED, () -> nullReceiver.receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            ));
            assertAllZero(nullKeyWrap.kek, nullKeyWrap.output, nullGcm.key, nullGcm.aad);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void authenticatedMalformedInnerFailureStillClearsPlaintextAndSecrets() {
        try (RealFixture fixture = new RealFixture()) {
            String maliciousWire = fixture.authenticatedWire("{".getBytes(StandardCharsets.UTF_8));
            RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm gcm = new RecordingGcm(fixture.gcm);
            PublicX25519UnsignedReceiver receiver = new PublicX25519UnsignedReceiver(
                    fixture.deriver, keyWrap, gcm
            );

            assertCode(ErrorCode.MALFORMED_WIRE, () -> receiver.receive(
                    fixture.request(maliciousWire, List.of(fixture.second))
            ));
            assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad, gcm.plaintext);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void requestSnapshotsHandleListAndAllowsEmptyListForNotForMe() {
        try (RealFixture fixture = new RealFixture()) {
            ArrayList<X25519PrivateKeyHandle> callerHandles = new ArrayList<>();
            callerHandles.add(fixture.second);
            PublicX25519UnsignedReceiver.Request snapshot = fixture.request(
                    fixture.wire, callerHandles
            );
            callerHandles.clear();

            assertArrayEquals(
                    fixture.payload.data(),
                    fixture.receiver().receive(snapshot).payload().data()
            );
            assertEquals(1, snapshot.recipientPrivateKeys().size());

            PublicX25519UnsignedReceiver.Request empty = fixture.request(fixture.wire, List.of());
            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(empty));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void closedOrForeignMatchingLocalHandleIsInternalRatherThanNotForMe() {
        try (RealFixture fixture = new RealFixture()) {
            byte[] targetPublic = fixture.second.publicKey();
            X25519PrivateKeyHandle foreign = new X25519PrivateKeyHandle() {
                @Override
                public byte[] publicKey() {
                    return targetPublic.clone();
                }

                @Override
                public void close() {
                }
            };
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(fixture.wire, List.of(foreign))
            ));
            assertEquals(32, foreign.publicKey().length);

            fixture.second.close();
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(fixture.wire, List.of(fixture.second))
            ));
            Arrays.fill(targetPublic, (byte) 0);
        }
    }

    @Test
    void validatesConstructorAndRequestDependenciesWithoutBypassingStrictParser() {
        try (RealFixture fixture = new RealFixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver(null, fixture.keyWrap, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver(fixture.deriver, null, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver(fixture.deriver, fixture.keyWrap, null));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver.Request(fixture.wire, null, List.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver.Request(fixture.wire, kid -> Optional.empty(), null));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicX25519UnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.empty(), Arrays.asList((X25519PrivateKeyHandle) null)
                    ));
            assertThrows(IllegalArgumentException.class, () -> fixture.receiver().receive(null));

            PublicX25519UnsignedReceiver.Request nullWire = new PublicX25519UnsignedReceiver.Request(
                    null, kid -> Optional.empty(), List.of()
            );
            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(nullWire));
        }
    }

    private static String tamperTopLevelBytes(String wire, String field) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            byte[] value = Base64Url.decodeCanonical(root.get(field).textValue(), "test." + field);
            value[0] ^= 1;
            root.put(field, Base64Url.encode(value));
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to prepare tampered wire", e);
        }
    }

    private static void assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        assertFalse(failure.errorCode() == ErrorCode.NOT_FOR_ME && expected != ErrorCode.NOT_FOR_ME);
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

    private static final class RealFixture implements AutoCloseable {
        private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        private final PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                x25519, new BouncyCastleHkdfCrypto()
        );
        private final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        private final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        private final X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle first = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle second = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle unrelated = x25519.generatePrivateKey();
        private final ProtocolPayload payload = new ProtocolPayload(
                "application/octet-stream", new byte[]{0, 1, 2, (byte) 0xff}, 4
        );
        private final String wire;

        private RealFixture() {
            PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                    new PublicX25519RecipientBuilder(deriver, keyWrap), gcm
            );
            wire = sender.send(new PublicX25519UnsignedSender.Request(
                    payload,
                    MESSAGE_ID,
                    TIMESTAMP,
                    senderKey,
                    List.of(first.publicKey(), second.publicKey())
            )).wireJson();
        }

        private PublicX25519UnsignedReceiver receiver() {
            return new PublicX25519UnsignedReceiver(deriver, keyWrap, gcm);
        }

        private PublicX25519UnsignedReceiver.Request request(
                String candidateWire,
                List<X25519PrivateKeyHandle> handles
        ) {
            return new PublicX25519UnsignedReceiver.Request(
                    candidateWire, kid -> Optional.of(senderKey.publicKey()), handles
            );
        }

        private String authenticatedWire(byte[] innerBytes) {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            PublicRecipient recipient = (PublicRecipient) parsed.recipients().get(1);
            byte[] senderPublic = senderKey.publicKey();
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
                Arrays.fill(senderPublic, (byte) 0);
                Arrays.fill(kek, (byte) 0);
                Arrays.fill(cek, (byte) 0);
                Arrays.fill(aad, (byte) 0);
            }
        }

        @Override
        public void close() {
            unrelated.close();
            second.close();
            first.close();
            senderKey.close();
        }
    }
}
