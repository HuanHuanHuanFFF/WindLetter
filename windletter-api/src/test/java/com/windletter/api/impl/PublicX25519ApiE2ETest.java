package com.windletter.api.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.windletter.api.WindLetterReceiver;
import com.windletter.api.WindLetterSender;
import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.VerificationPolicy;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.api.enums.WindMode;
import com.windletter.api.model.DecryptRequest;
import com.windletter.api.model.DecryptResult;
import com.windletter.api.model.EncryptAndSignRequest;
import com.windletter.api.model.EncryptRequest;
import com.windletter.api.model.EncryptedMessage;
import com.windletter.api.model.Payload;
import com.windletter.api.model.RecipientIdentityRef;
import com.windletter.api.model.RecipientRef;
import com.windletter.api.model.SenderEncryptionIdentityRef;
import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import com.windletter.api.spi.DecryptionKeyLease;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientKeyStore;
import com.windletter.api.spi.RecipientPublicKeyMaterial;
import com.windletter.api.spi.RecipientPublicKeyResolver;
import com.windletter.api.spi.SenderEncryptionKeyLease;
import com.windletter.api.spi.SenderEncryptionKeyStore;
import com.windletter.api.spi.SenderPublicKeyResolver;
import com.windletter.api.spi.SigningIdentityLease;
import com.windletter.api.spi.VerificationKeyMaterial;
import com.windletter.api.spi.X25519PublicKeyMaterial;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PublicX25519ApiE2ETest {

    @Test
    void publicX25519UnsignedRoundTripsThroughOnlyPublicApiAndClosesLeases() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            Payload payload = new Payload(
                "application/octet-stream",
                new byte[] {0, 1, (byte) 0xff, 0},
                4
            );

            EncryptedMessage encrypted = sender.encrypt(new EncryptRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null)
            ));

            assertEquals(ArmorFormat.NONE, encrypted.armorFormat());
            assertNull(encrypted.armor());
            assertNull(encrypted.armorBytes());
            assertTrue(encrypted.wireJson().startsWith("{"));
            assertClosed(keys.lastSenderEncryption);

            DecryptResult result = receiver.decrypt(new DecryptRequest(
                encrypted.wireJson(),
                null,
                null,
                ArmorFormat.NONE,
                new RecipientIdentityRef("recipient-2", null),
                VerificationPolicy.AUTO_BY_CTY
            ));

            assertEquals(DecryptStatus.SUCCESS, result.status());
            assertEquals(VerificationStatus.UNSIGNED, result.verificationStatus());
            assertNull(result.senderIdentity());
            assertEquals(payload.contentType(), result.payload().contentType());
            assertArrayEquals(payload.data(), result.payload().data());
            assertEquals(payload.originalSize(), result.payload().originalSize());
            assertUuidV4(result.messageId());
            assertTrue(result.timestamp() > 0);
            assertClosed(keys.lastRecipient);
        }
    }

    @Test
    void publicX25519SignedVerifiesIdentityThroughOnlyPublicApiAndClosesAllLeases() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            Payload payload = new Payload("text/plain;charset=UTF-8", "signed hello".getBytes(), 12);

            EncryptedMessage encrypted = sender.encryptAndSign(new EncryptAndSignRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null),
                new SigningIdentityRef("signer", keys.signingKid)
            ));

            assertClosed(keys.lastSenderEncryption);
            assertClosed(keys.lastSigning);

            DecryptResult result = receiver.decrypt(new DecryptRequest(
                encrypted.wireJson(),
                null,
                null,
                ArmorFormat.NONE,
                new RecipientIdentityRef("recipient-1", null),
                VerificationPolicy.ALLOW_UNSIGNED
            ));

            assertEquals(DecryptStatus.SUCCESS, result.status());
            assertEquals(VerificationStatus.SIGNED_VALID, result.verificationStatus());
            assertEquals(
                new SenderIdentity("trusted-sender", keys.signingKid, Map.of("display", "Sender")),
                result.senderIdentity()
            );
            assertArrayEquals(payload.data(), result.payload().data());
            assertUuidV4(result.messageId());
            assertClosed(keys.lastRecipient);
            assertEquals(1, keys.verificationLookups);
            assertEquals(1, keys.identityLookups);
        }
    }

    @Test
    void allowUnsignedMustNotDowngradeAnAuthenticatedWireWithAnInvalidSignature() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            byte[] data = "must stay signed".getBytes(StandardCharsets.UTF_8);
            EncryptedMessage encrypted = sender.encryptAndSign(new EncryptAndSignRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                new Payload("text/plain;charset=UTF-8", data, data.length),
                keys.recipientRefs(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null),
                new SigningIdentityRef("signer", keys.signingKid)
            ));
            String invalidSignatureWire = reencryptWithInvalidSignature(encrypted.wireJson(), keys);

            DecryptResult result = receiver.decrypt(new DecryptRequest(
                invalidSignatureWire,
                null,
                null,
                ArmorFormat.NONE,
                new RecipientIdentityRef("recipient-1", null),
                VerificationPolicy.ALLOW_UNSIGNED
            ));

            assertEquals(DecryptStatus.INVALID_MESSAGE, result.status());
            assertEquals(VerificationStatus.FAILED, result.verificationStatus());
            assertEquals(com.windletter.core.error.ErrorCode.INVALID_MESSAGE, result.errorCode());
            assertNull(result.payload());
            assertNull(result.senderIdentity());
            assertNull(result.messageId());
            assertNull(result.timestamp());
            assertClosed(keys.lastRecipient);
        }
    }

    private static String reencryptWithInvalidSignature(String wireJson, Fixture keys) {
        WindLetter letter = new JacksonOuterWireParser().parse(wireJson);
        PublicRecipient recipient = letter.recipients().stream()
            .map(entry -> (PublicRecipient) entry)
            .filter(entry -> keys.recipient1Kid.equals(entry.kid().x25519()))
            .findFirst()
            .orElseThrow();

        byte[] wrappedKey = null;
        byte[] kek = null;
        byte[] cek = null;
        byte[] gcmAad = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] tag = null;
        byte[] inner = null;
        byte[] maliciousInner = null;
        byte[] changedCiphertext = null;
        byte[] changedTag = null;
        try (X25519PrivateKeyHandle recipientPrivate = keys.x25519.importPrivateKey(
            keys.recipient1Private
        )) {
            PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(
                new BouncyCastleX25519Crypto(),
                new BouncyCastleHkdfCrypto()
            );
            BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
            BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
            wrappedKey = recipient.encryptedKey();
            kek = kekDeriver.derive(recipientPrivate, keys.senderPublic);
            cek = keyWrap.unwrap(kek, wrappedKey);
            gcmAad = new OuterAad().gcmInput(letter.protectedValue(), letter.aad());
            iv = letter.iv();
            ciphertext = letter.ciphertext();
            tag = letter.tag();
            inner = gcm.decrypt(cek, iv, gcmAad, ciphertext, tag);

            String innerJson = new String(inner, StandardCharsets.UTF_8);
            int signatureStart = innerJson.indexOf("\"signature\":\"");
            if (signatureStart < 0) {
                throw new AssertionError("signed inner has no signature field");
            }
            signatureStart += "\"signature\":\"".length();
            char original = innerJson.charAt(signatureStart);
            char replacement = original == 'A' ? 'B' : 'A';
            String changedJson = innerJson.substring(0, signatureStart)
                + replacement
                + innerJson.substring(signatureStart + 1);
            maliciousInner = changedJson.getBytes(StandardCharsets.UTF_8);
            AeadCiphertext changed = gcm.encrypt(cek, iv, gcmAad, maliciousInner);
            changedCiphertext = changed.ciphertext();
            changedTag = changed.tag();
            return new JacksonOuterWireWriter().write(new WindLetter(
                letter.protectedHeader(),
                letter.protectedValue(),
                letter.aad(),
                letter.recipients(),
                iv,
                changedCiphertext,
                changedTag
            ));
        } finally {
            Fixture.clear(wrappedKey);
            Fixture.clear(kek);
            Fixture.clear(cek);
            Fixture.clear(gcmAad);
            Fixture.clear(iv);
            Fixture.clear(ciphertext);
            Fixture.clear(tag);
            Fixture.clear(inner);
            Fixture.clear(maliciousInner);
            Fixture.clear(changedCiphertext);
            Fixture.clear(changedTag);
        }
    }

    private static void assertUuidV4(String value) {
        UUID uuid = UUID.fromString(value);
        assertEquals(4, uuid.version());
        assertEquals(2, uuid.variant());
        assertEquals(uuid.toString(), value);
    }

    private static void assertClosed(X25519PrivateKeyHandle handle) {
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    private static void assertClosed(Ed25519PrivateKeyHandle handle) {
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    private static final class Fixture implements
        RecipientPublicKeyResolver,
        SenderEncryptionKeyStore,
        RecipientKeyStore,
        SenderPublicKeyResolver,
        IdentityService,
        AutoCloseable {

        private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        private final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        private final byte[] senderPrivate = privateBytes(11);
        private final byte[] recipient1Private = privateBytes(21);
        private final byte[] recipient2Private = privateBytes(31);
        private final byte[] signingPrivate = privateBytes(41);
        private final byte[] senderPublic = x25519Public(senderPrivate);
        private final byte[] recipient1Public = x25519Public(recipient1Private);
        private final byte[] recipient2Public = x25519Public(recipient2Private);
        private final byte[] signingPublic = ed25519Public(signingPrivate);
        private final String senderKid = X25519KeyId.derive(senderPublic);
        private final String recipient1Kid = X25519KeyId.derive(recipient1Public);
        private final String recipient2Kid = X25519KeyId.derive(recipient2Public);
        private final String signingKid = Ed25519KeyId.derive(signingPublic);

        private X25519PrivateKeyHandle lastSenderEncryption;
        private X25519PrivateKeyHandle lastRecipient;
        private Ed25519PrivateKeyHandle lastSigning;
        private int verificationLookups;
        private int identityLookups;

        List<RecipientRef> recipientRefs() {
            return List.of(
                new RecipientRef("recipient-1", recipient1Kid, null, Map.of()),
                new RecipientRef("recipient-2", recipient2Kid, null, Map.of())
            );
        }

        @Override
        public Optional<RecipientPublicKeyMaterial> resolve(RecipientRef recipient) {
            return switch (recipient.recipientId()) {
                case "recipient-1" -> Optional.of(new RecipientPublicKeyMaterial(
                    recipient1Kid,
                    recipient1Public,
                    null,
                    null
                ));
                case "recipient-2" -> Optional.of(new RecipientPublicKeyMaterial(
                    recipient2Kid,
                    recipient2Public,
                    null,
                    null
                ));
                default -> Optional.empty();
            };
        }

        @Override
        public Optional<SenderEncryptionKeyLease> open(SenderEncryptionIdentityRef identity) {
            if (!"sender".equals(identity.identityId())) {
                return Optional.empty();
            }
            lastSenderEncryption = x25519.importPrivateKey(senderPrivate);
            return Optional.of(SenderEncryptionKeyLease.x25519(senderKid, lastSenderEncryption));
        }

        @Override
        public List<DecryptionKeyLease> openAll(RecipientIdentityRef identity) {
            if ("recipient-1".equals(identity.recipientId())) {
                lastRecipient = x25519.importPrivateKey(recipient1Private);
                return List.of(DecryptionKeyLease.x25519(recipient1Kid, lastRecipient));
            }
            if ("recipient-2".equals(identity.recipientId())) {
                lastRecipient = x25519.importPrivateKey(recipient2Private);
                return List.of(DecryptionKeyLease.x25519(recipient2Kid, lastRecipient));
            }
            return List.of();
        }

        @Override
        public Optional<X25519PublicKeyMaterial> resolveX25519ByKid(String kid) {
            return senderKid.equals(kid)
                ? Optional.of(new X25519PublicKeyMaterial(senderKid, senderPublic))
                : Optional.empty();
        }

        @Override
        public Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef identity) {
            if (!"signer".equals(identity.identityId())) {
                return Optional.empty();
            }
            lastSigning = ed25519.importPrivateKey(signingPrivate);
            return Optional.of(SigningIdentityLease.ed25519("signer", signingKid, lastSigning));
        }

        @Override
        public Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String kid) {
            verificationLookups++;
            return signingKid.equals(kid)
                ? Optional.of(new VerificationKeyMaterial(signingKid, signingPublic, Map.of()))
                : Optional.empty();
        }

        @Override
        public Optional<SenderIdentity> resolveSenderBySigningKid(String kid) {
            identityLookups++;
            return signingKid.equals(kid)
                ? Optional.of(new SenderIdentity(
                    "trusted-sender",
                    signingKid,
                    Map.of("display", "Sender")
                ))
                : Optional.empty();
        }

        private byte[] x25519Public(byte[] privateKey) {
            try (X25519PrivateKeyHandle handle = x25519.importPrivateKey(privateKey)) {
                return handle.publicKey();
            }
        }

        private byte[] ed25519Public(byte[] privateKey) {
            try (Ed25519PrivateKeyHandle handle = ed25519.importPrivateKey(privateKey)) {
                return handle.publicKey();
            }
        }

        @Override
        public void close() {
            Fixture.clear(senderPrivate);
            Fixture.clear(recipient1Private);
            Fixture.clear(recipient2Private);
            Fixture.clear(signingPrivate);
            Fixture.clear(senderPublic);
            Fixture.clear(recipient1Public);
            Fixture.clear(recipient2Public);
            Fixture.clear(signingPublic);
        }

        private static byte[] privateBytes(int seed) {
            byte[] value = new byte[32];
            for (int i = 0; i < value.length; i++) {
                value[i] = (byte) (seed + i);
            }
            return value;
        }

        private static void clear(byte[] value) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
