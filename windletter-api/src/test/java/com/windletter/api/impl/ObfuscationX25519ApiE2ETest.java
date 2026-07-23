package com.windletter.api.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ObfuscationX25519ApiE2ETest {

    @Test
    void unsignedUsesRealBucketPaddingAndRoutesSecondInputRecipient() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            Payload payload = new Payload(
                "application/octet-stream",
                new byte[] {0, (byte) 0xff, 7, 0},
                4
            );

            EncryptedMessage encrypted = sender.encrypt(new EncryptRequest(
                WindMode.OBFUSCATION,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                null
            ));

            assertEquals(
                8,
                new JacksonOuterWireParser().parse(encrypted.wireJson()).recipients().size()
            );
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
            assertArrayEquals(payload.data(), result.payload().data());
            assertEquals(0, keys.senderEncryptionOpens);
            assertClosed(keys.lastRecipient);
        }
    }

    @Test
    void signedUsesEphemeralEncryptionAndReturnsOnlyVerifiedIdentity() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            byte[] data = "obfuscation signed".getBytes(StandardCharsets.UTF_8);
            Payload payload = new Payload("text/plain;charset=UTF-8", data, data.length);

            EncryptedMessage encrypted = sender.encryptAndSign(new EncryptAndSignRequest(
                WindMode.OBFUSCATION,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                null,
                new SigningIdentityRef("signer", keys.signingKid)
            ));

            DecryptResult result = receiver.decryptAndVerify(new DecryptRequest(
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
                new SenderIdentity("trusted-sender", keys.signingKid, Map.of("role", "demo")),
                result.senderIdentity()
            );
            assertArrayEquals(payload.data(), result.payload().data());
            assertEquals(0, keys.senderEncryptionOpens);
            assertClosed(keys.lastSigning);
            assertClosed(keys.lastRecipient);
        }
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
        private final byte[] recipient1Private = privateBytes(21);
        private final byte[] recipient2Private = privateBytes(31);
        private final byte[] signingPrivate = privateBytes(41);
        private final byte[] recipient1Public = x25519Public(recipient1Private);
        private final byte[] recipient2Public = x25519Public(recipient2Private);
        private final byte[] signingPublic = ed25519Public(signingPrivate);
        private final String recipient1Kid = X25519KeyId.derive(recipient1Public);
        private final String recipient2Kid = X25519KeyId.derive(recipient2Public);
        private final String signingKid = Ed25519KeyId.derive(signingPublic);

        private int senderEncryptionOpens;
        private X25519PrivateKeyHandle lastRecipient;
        private Ed25519PrivateKeyHandle lastSigning;

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
            senderEncryptionOpens++;
            throw new AssertionError("obfuscation must not open a static sender encryption key");
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
            throw new AssertionError(
                "obfuscation must not resolve a static sender encryption public key"
            );
        }

        @Override
        public Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef identity) {
            if (!"signer".equals(identity.identityId())) {
                return Optional.empty();
            }
            lastSigning = ed25519.importPrivateKey(signingPrivate);
            return Optional.of(SigningIdentityLease.ed25519(
                "signer",
                signingKid,
                lastSigning
            ));
        }

        @Override
        public Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String kid) {
            return signingKid.equals(kid)
                ? Optional.of(new VerificationKeyMaterial(signingKid, signingPublic, Map.of()))
                : Optional.empty();
        }

        @Override
        public Optional<SenderIdentity> resolveSenderBySigningKid(String kid) {
            return signingKid.equals(kid)
                ? Optional.of(new SenderIdentity(
                    "trusted-sender",
                    signingKid,
                    Map.of("role", "demo")
                ))
                : Optional.empty();
        }

        @Override
        public void close() {
            clear(signingPrivate);
            clear(recipient2Private);
            clear(recipient1Private);
            clear(signingPublic);
            clear(recipient2Public);
            clear(recipient1Public);
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
