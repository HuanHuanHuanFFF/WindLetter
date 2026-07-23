package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.routing.ObfuscationHybridCekRecovery;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridUnsignedReceiverTest {

    @Test
    void parsesAuthenticatesRecoversDecryptsAndChecksBindingInOrder() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String wire = fixture.send(fixture.binaryPayload());
            ObfuscationHybridUnsignedReceiver receiver = fixture.receiver();

            assertProtocolCode(ErrorCode.MALFORMED_WIRE, () -> receiver.receive(
                    fixture.request("{", List.of(fixture.first.privateKeys()))
            ));

            try (ObfuscationX25519FlowTestFixtures.Fixture otherProfile =
                         new ObfuscationX25519FlowTestFixtures.Fixture()) {
                String x25519Wire = otherProfile.send(otherProfile.binaryPayload());
                assertProtocolCode(ErrorCode.UNSUPPORTED_ALGORITHM, () ->
                        receiver.receive(fixture.request(
                                x25519Wire,
                                Arrays.asList(
                                        (ObfuscationHybridRecipientPrivateKeys) null
                                )
                        ))
                );
            }

            ObjectNode badAad = ProtocolFlowTestFixtures.parseObject(wire);
            badAad.put("aad", Base64Url.encode(new byte[]{1}));
            List<ObfuscationHybridRecipientPrivateKeys> poisoned =
                    Arrays.asList((ObfuscationHybridRecipientPrivateKeys) null);
            assertProtocolCode(ErrorCode.AAD_MISMATCH, () -> receiver.receive(
                    fixture.request(
                            ProtocolFlowTestFixtures.write(badAad),
                            poisoned
                    )
            ));

            ObjectNode duplicateRid = ProtocolFlowTestFixtures.parseObject(wire);
            ArrayNode duplicateRecipients = duplicateRid.withArray("recipients");
            ((ObjectNode) duplicateRecipients.get(1)).put(
                    "rid", duplicateRecipients.get(0).get("rid").textValue()
            );
            ProtocolFlowTestFixtures.recomputeAad(duplicateRid);
            assertProtocolCode(ErrorCode.INVALID_FIELD, () -> receiver.receive(
                    fixture.request(
                            ProtocolFlowTestFixtures.write(duplicateRid), poisoned
                    )
            ));
            assertProtocolCode(ErrorCode.INTERNAL_ERROR, () -> receiver.receive(
                    fixture.request(wire, poisoned)
            ));

            assertProtocolCode(ErrorCode.NOT_FOR_ME, () -> receiver.receive(
                    fixture.request(wire, List.of(fixture.unrelated.privateKeys()))
            ));

            ObjectNode badCiphertext = ProtocolFlowTestFixtures.parseObject(wire);
            byte[] ciphertext = Base64Url.decodeCanonical(
                    badCiphertext.get("ciphertext").textValue(), "test.ciphertext"
            );
            try {
                ciphertext[0] ^= 1;
                badCiphertext.put("ciphertext", Base64Url.encode(ciphertext));
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(ciphertext);
            }
            RecordingKeyWrap failedWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm failedGcm = new RecordingGcm(fixture.gcm);
            ObfuscationHybridUnsignedReceiver failedReceiver =
                    new ObfuscationHybridUnsignedReceiver(
                            new ObfuscationHybridCekRecovery(
                                    fixture.keyDeriver, failedWrap
                            ),
                            failedGcm
                    );
            assertProtocolCode(ErrorCode.GCM_AUTH_FAILED, () -> failedReceiver.receive(
                    fixture.request(
                            ProtocolFlowTestFixtures.write(badCiphertext),
                            List.of(fixture.middle.privateKeys())
                    )
            ));
            assertAllZero(
                    failedWrap.kek,
                    failedWrap.output,
                    failedGcm.key,
                    failedGcm.aad
            );

            assertProtocolCode(ErrorCode.BINDING_FAILED, () -> receiver.receive(
                    fixture.request(
                            fixture.authenticatedWrongBinding(wire, fixture.middle),
                            List.of(fixture.middle.privateKeys())
                    )
            ));

            RecordingKeyWrap successfulWrap = new RecordingKeyWrap(fixture.keyWrap);
            RecordingGcm successfulGcm = new RecordingGcm(fixture.gcm);
            ObfuscationHybridUnsignedReceiver successfulReceiver =
                    new ObfuscationHybridUnsignedReceiver(
                            new ObfuscationHybridCekRecovery(
                                    fixture.keyDeriver, successfulWrap
                            ),
                            successfulGcm
                    );
            ObfuscationHybridUnsignedReceiver.Result result = successfulReceiver.receive(
                    fixture.request(wire, List.of(fixture.middle.privateKeys()))
            );
            assertArrayEquals(
                    ProtocolFlowTestFixtures.BINARY_PAYLOAD, result.payload().data()
            );
            assertEquals(ProtocolFlowTestFixtures.MESSAGE_ID, result.messageId());
            assertEquals(ProtocolFlowTestFixtures.TIMESTAMP, result.timestamp());
            assertEquals(
                    ProtocolAuthenticationStatus.UNSIGNED,
                    result.authenticationStatus()
            );
            assertEquals(32, fixture.middle.x25519.publicKey().length);
            assertEquals(1184, fixture.middle.mlkem768.publicKey().length);
            assertAllZero(
                    successfulWrap.kek,
                    successfulWrap.output,
                    successfulGcm.key,
                    successfulGcm.aad,
                    successfulGcm.plaintext
            );
        }
    }

    @Test
    void requestOnlySnapshotsBorrowedPairReferencesAndDefersLocalValidation() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridUnsignedReceiver(null, fixture.gcm));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridUnsignedReceiver(fixture.recovery(), null));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridUnsignedReceiver.Request("{}", null));
            ObfuscationHybridUnsignedReceiver.Request poisoned =
                    new ObfuscationHybridUnsignedReceiver.Request(
                            "{", Arrays.asList((ObfuscationHybridRecipientPrivateKeys) null)
                    );
            assertNull(poisoned.recipientPrivateKeys().get(0));
            assertProtocolCode(ErrorCode.MALFORMED_WIRE, () ->
                    fixture.receiver().receive(poisoned));

            ArrayList<ObfuscationHybridRecipientPrivateKeys> caller =
                    new ArrayList<>(List.of(fixture.first.privateKeys()));
            ObfuscationHybridUnsignedReceiver.Request request =
                    new ObfuscationHybridUnsignedReceiver.Request("{}", caller);
            caller.clear();
            assertSame(fixture.first.x25519,
                    request.recipientPrivateKeys().get(0).x25519PrivateKey());
            assertThrows(UnsupportedOperationException.class, () ->
                    request.recipientPrivateKeys().add(fixture.middle.privateKeys()));
            assertThrows(IllegalArgumentException.class, () ->
                    fixture.receiver().receive(null));
            assertEquals(32, fixture.first.x25519.publicKey().length);
            assertEquals(1184, fixture.first.mlkem768.publicKey().length);
        }
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            for (byte current : value) {
                assertEquals(0, current);
            }
        }
    }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(A256KeyWrapCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            return delegate.wrap(kek, keyToWrap);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            this.kek = kek;
            output = delegate.unwrap(kek, wrappedKey);
            return output;
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] plaintext
        ) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag
        ) {
            this.key = key;
            this.aad = aad;
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }
}
