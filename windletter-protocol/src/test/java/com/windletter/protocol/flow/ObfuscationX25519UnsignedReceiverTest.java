package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.routing.ObfuscationX25519CekRecovery;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519UnsignedReceiverTest {

    @Test
    void receivesRealWireAndClearsRecoveryGcmAndInnerArraysWithoutClosingBorrowedHandle() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());
            RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap, WrapMode.DELEGATE);
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
            ObfuscationX25519UnsignedReceiver receiver = new ObfuscationX25519UnsignedReceiver(
                    new ObfuscationX25519CekRecovery(
                            new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf), keyWrap
                    ), gcm
            );

            ObfuscationX25519UnsignedReceiver.Result result = receiver.receive(
                    new ObfuscationX25519UnsignedReceiver.Request(wire, List.of(fixture.second))
            );

            assertArrayEquals(fixture.binaryPayload().data(), result.payload().data());
            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.UNSIGNED, result.authenticationStatus());
            assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad, gcm.plaintext);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void parserProfileAadRecoveryGcmInnerAndBindingGatesRunInThatOrder() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());
            List<X25519PrivateKeyHandle> poisoned = Arrays.asList((X25519PrivateKeyHandle) null);

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    fixture.request("{", poisoned)));

            String profile = new PublicX25519UnsignedSender(
                    new PublicX25519RecipientBuilder(
                            new PublicX25519KekDeriver(fixture.x25519, fixture.hkdf), fixture.keyWrap),
                    fixture.gcm
            ).send(new PublicX25519UnsignedSender.Request(
                    fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, fixture.first,
                    List.of(fixture.second.publicKey())
            )).wireJson();
            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> fixture.receiver().receive(
                    fixture.request(profile, poisoned)));

            ObjectNode badAad = object(wire);
            badAad.put("aad", Base64Url.encode(new byte[]{1}));
            assertCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    fixture.request(json(badAad), poisoned)));

            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(wire, poisoned)));

            ObjectNode badCiphertext = object(wire);
            flipFirstByte(badCiphertext, "ciphertext");
            assertCode(ErrorCode.GCM_AUTH_FAILED, () -> fixture.receiver().receive(
                    fixture.request(json(badCiphertext), List.of(fixture.second))));

            String malformedInner = fixture.authenticatedWire(
                    wire, "{".getBytes(StandardCharsets.UTF_8));
            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    fixture.request(malformedInner, List.of(fixture.second))));

            assertCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                    fixture.request(fixture.bindingFailure(wire), List.of(fixture.second))));
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void preservesNotForMeKeyRecoveryAndHandleContractErrorAppearances() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());
            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                    fixture.request(wire, List.of())));
            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                    fixture.request(wire, List.of(fixture.unrelated))));

            ObjectNode wrapped = object(wire);
            ArrayNode recipients = (ArrayNode) wrapped.get("recipients");
            for (int i = 0; i < recipients.size(); i++) {
                ObjectNode recipient = (ObjectNode) recipients.get(i);
                byte[] encrypted = Base64Url.decodeCanonical(
                        recipient.get("encrypted_key").textValue(), "test.encrypted_key");
                try {
                    encrypted[0] ^= 1;
                    recipient.put("encrypted_key", Base64Url.encode(encrypted));
                } finally {
                    clear(encrypted);
                }
            }
            recomputeAad(wrapped);
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> fixture.receiver().receive(
                    fixture.request(json(wrapped), List.of(fixture.second))));

            byte[] matchingPublic = fixture.second.publicKey();
            X25519PrivateKeyHandle foreign = new X25519PrivateKeyHandle() {
                @Override public byte[] publicKey() { return matchingPublic.clone(); }
                @Override public void close() { }
            };
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(wire, List.of(foreign))));

            X25519PrivateKeyHandle closed = fixture.x25519.generatePrivateKey();
            closed.close();
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.request(wire, List.of(closed))));
            assertEquals(32, fixture.unrelated.publicKey().length);
            clear(matchingPublic);
        }
    }

    @Test
    void mapsGcmRuntimeAndNullToAuthFailureAndClearsRecoveredArrays() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());
            for (GcmMode mode : List.of(GcmMode.FAIL, GcmMode.NULL)) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap, WrapMode.DELEGATE);
                RecordingGcm gcm = new RecordingGcm(fixture.gcm, mode);
                ObfuscationX25519UnsignedReceiver receiver = new ObfuscationX25519UnsignedReceiver(
                        new ObfuscationX25519CekRecovery(
                                new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf), keyWrap
                        ), gcm
                );
                assertCode(ErrorCode.GCM_AUTH_FAILED, () -> receiver.receive(
                        fixture.request(wire, List.of(fixture.second))));
                assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad);
                if (gcm.plaintext != null) assertTrue(allZero(gcm.plaintext));
            }
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void recoveryAndInnerFailuresClearProviderOutputsAndDecryptedInner() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());

            RecordingKeyWrap failingWrap = new RecordingKeyWrap(fixture.keyWrap, WrapMode.FAIL);
            RecordingGcm unusedGcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
            ObfuscationX25519UnsignedReceiver recoveryFailure =
                    new ObfuscationX25519UnsignedReceiver(
                            new ObfuscationX25519CekRecovery(
                                    new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf),
                                    failingWrap), unusedGcm);
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> recoveryFailure.receive(
                    fixture.request(wire, List.of(fixture.second))));
            assertTrue(allZero(failingWrap.kek));
            assertEquals(0, unusedGcm.decryptCalls);

            String malformed = fixture.authenticatedWire(
                    wire, "{".getBytes(StandardCharsets.UTF_8));
            RecordingKeyWrap successfulWrap = new RecordingKeyWrap(
                    fixture.keyWrap, WrapMode.DELEGATE);
            RecordingGcm recordingGcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
            ObfuscationX25519UnsignedReceiver innerFailure =
                    new ObfuscationX25519UnsignedReceiver(
                            new ObfuscationX25519CekRecovery(
                                    new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf),
                                    successfulWrap), recordingGcm);
            assertCode(ErrorCode.MALFORMED_WIRE, () -> innerFailure.receive(
                    fixture.request(malformed, List.of(fixture.second))));
            assertAllZero(successfulWrap.kek, successfulWrap.output,
                    recordingGcm.key, recordingGcm.aad, recordingGcm.plaintext);

            String badBinding = fixture.bindingFailure(wire);
            RecordingKeyWrap bindingWrap = new RecordingKeyWrap(
                    fixture.keyWrap, WrapMode.DELEGATE);
            RecordingGcm bindingGcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
            ObfuscationX25519UnsignedReceiver bindingFailure =
                    new ObfuscationX25519UnsignedReceiver(
                            new ObfuscationX25519CekRecovery(
                                    new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf),
                                    bindingWrap), bindingGcm);
            assertCode(ErrorCode.BINDING_FAILED, () -> bindingFailure.receive(
                    fixture.request(badBinding, List.of(fixture.second))));
            assertAllZero(bindingWrap.kek, bindingWrap.output,
                    bindingGcm.key, bindingGcm.aad, bindingGcm.plaintext);

            RecordingKeyWrap malformedWrap = new RecordingKeyWrap(
                    fixture.keyWrap, WrapMode.WRONG_LENGTH);
            ObfuscationX25519UnsignedReceiver malformedRecovery =
                    new ObfuscationX25519UnsignedReceiver(
                            new ObfuscationX25519CekRecovery(
                                    new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf),
                                    malformedWrap), fixture.gcm);
            assertCode(ErrorCode.KEY_UNWRAP_FAILED, () -> malformedRecovery.receive(
                    fixture.request(wire, List.of(fixture.second))));
            assertAllZero(malformedWrap.kek, malformedWrap.output);
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void requestSnapshotsOnlyTheListAndValidatesConstructorAndResultContracts() {
        try (Fixture fixture = new Fixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedReceiver(null, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedReceiver(fixture.recovery(), null));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519UnsignedReceiver.Request("{}", null));
            assertThrows(IllegalArgumentException.class, () -> fixture.receiver().receive(null));

            String wire = fixture.send(fixture.emptyPayload());
            ArrayList<X25519PrivateKeyHandle> handles = new ArrayList<>();
            handles.add(fixture.first);
            ObfuscationX25519UnsignedReceiver.Request request =
                    new ObfuscationX25519UnsignedReceiver.Request(wire, handles);
            handles.clear();
            assertSame(fixture.first, request.recipientPrivateKeys().get(0));
            assertThrows(UnsupportedOperationException.class,
                    () -> request.recipientPrivateKeys().add(fixture.second));
            assertArrayEquals(new byte[0], fixture.receiver().receive(request).payload().data());

            ObfuscationX25519UnsignedReceiver.Request nullWire =
                    new ObfuscationX25519UnsignedReceiver.Request(null, List.of());
            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(nullWire));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationX25519UnsignedReceiver.Result(
                            null, MESSAGE_ID, TIMESTAMP, ProtocolAuthenticationStatus.UNSIGNED));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationX25519UnsignedReceiver.Result(
                            fixture.binaryPayload(), null, TIMESTAMP,
                            ProtocolAuthenticationStatus.UNSIGNED));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationX25519UnsignedReceiver.Result(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP, null));
        }
    }

    private static void flipFirstByte(ObjectNode root, String field) {
        byte[] decoded = Base64Url.decodeCanonical(root.get(field).textValue(), "test." + field);
        try {
            decoded[0] ^= 1;
            root.put(field, Base64Url.encode(decoded));
        } finally {
            clear(decoded);
        }
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            assertTrue(allZero(value), "receiver-owned array was not cleared");
        }
    }

    private enum WrapMode { DELEGATE, FAIL, WRONG_LENGTH }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private final WrapMode mode;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(A256KeyWrapCrypto delegate, WrapMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            return delegate.wrap(kek, keyToWrap);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            this.kek = kek;
            if (mode == WrapMode.FAIL) throw new CryptoOperationException("intentional unwrap failure");
            output = mode == WrapMode.WRONG_LENGTH
                    ? filled(31, 0x45)
                    : delegate.unwrap(kek, wrappedKey);
            return output;
        }
    }

    private enum GcmMode { DELEGATE, FAIL, NULL }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final GcmMode mode;
        private int decryptCalls;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate, GcmMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
            decryptCalls++;
            this.key = key;
            this.aad = aad;
            if (mode == GcmMode.FAIL) throw new CryptoOperationException("intentional GCM failure");
            if (mode == GcmMode.NULL) return null;
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }
}
