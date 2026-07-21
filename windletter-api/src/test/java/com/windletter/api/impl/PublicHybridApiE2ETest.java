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
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.X25519KeyId;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class PublicHybridApiE2ETest {

    @Test
    void publicHybridUnsignedUsesRealMlKemForANonFirstRecipient() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            Payload payload = new Payload(
                "application/octet-stream",
                new byte[] {0, (byte) 0xff, 7, 0},
                4
            );

            EncryptedMessage encrypted = sender.encrypt(new EncryptRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519_ML_KEM_768,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null)
            ));

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
            assertClosed(keys.senderX25519);
            assertClosed(keys.recipient2X25519);
            assertClosed(keys.recipient2MlKem);
        }
    }

    @Test
    void publicHybridAcceptsASingleRecipientKidHint() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            byte[] data = "single Hybrid hint".getBytes(StandardCharsets.UTF_8);
            Payload payload = new Payload("text/plain;charset=UTF-8", data, data.length);

            EncryptedMessage encrypted = sender.encrypt(new EncryptRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519_ML_KEM_768,
                ArmorFormat.NONE,
                payload,
                List.of(new RecipientRef(
                    "recipient-1",
                    keys.recipient1XKid,
                    null,
                    Map.of()
                )),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null)
            ));

            DecryptResult result = receiver.decrypt(new DecryptRequest(
                encrypted.wireJson(),
                null,
                null,
                ArmorFormat.NONE,
                new RecipientIdentityRef("recipient-1", null),
                VerificationPolicy.AUTO_BY_CTY
            ));

            assertEquals(DecryptStatus.SUCCESS, result.status());
            assertArrayEquals(payload.data(), result.payload().data());
        }
    }

    @Test
    void publicHybridSignedUsesRealMlKemAndReturnsOnlyVerifiedIdentity() {
        try (Fixture keys = new Fixture()) {
            WindLetterSender sender = new DefaultWindLetterSender(keys, keys, keys);
            WindLetterReceiver receiver = new DefaultWindLetterReceiver(keys, keys, keys);
            byte[] data = "hybrid signed".getBytes(StandardCharsets.UTF_8);
            Payload payload = new Payload("text/plain;charset=UTF-8", data, data.length);

            EncryptedMessage encrypted = sender.encryptAndSign(new EncryptAndSignRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519_ML_KEM_768,
                ArmorFormat.NONE,
                payload,
                keys.recipientRefs(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null),
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
            assertClosed(keys.senderX25519);
            assertClosed(keys.signingKey);
            assertClosed(keys.recipient1X25519);
            assertClosed(keys.recipient1MlKem);
        }
    }

    private static void assertClosed(X25519PrivateKeyHandle handle) {
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    private static void assertClosed(MLKem768PrivateKeyHandle handle) {
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
        private final BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        private final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        private final X25519PrivateKeyHandle senderX25519 = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle recipient1X25519 = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle recipient1MlKem = mlkem.generatePrivateKey();
        private final X25519PrivateKeyHandle recipient2X25519 = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle recipient2MlKem = mlkem.generatePrivateKey();
        private final Ed25519PrivateKeyHandle signingKey = ed25519.generatePrivateKey();
        private final byte[] senderPublic = senderX25519.publicKey();
        private final byte[] recipient1XPublic = recipient1X25519.publicKey();
        private final byte[] recipient1MlPublic = recipient1MlKem.publicKey();
        private final byte[] recipient2XPublic = recipient2X25519.publicKey();
        private final byte[] recipient2MlPublic = recipient2MlKem.publicKey();
        private final byte[] signingPublic = signingKey.publicKey();
        private final String senderKid = X25519KeyId.derive(senderPublic);
        private final String recipient1XKid = X25519KeyId.derive(recipient1XPublic);
        private final String recipient1MlKid = MLKem768KeyId.derive(recipient1MlPublic);
        private final String recipient2XKid = X25519KeyId.derive(recipient2XPublic);
        private final String recipient2MlKid = MLKem768KeyId.derive(recipient2MlPublic);
        private final String signingKid = Ed25519KeyId.derive(signingPublic);

        List<RecipientRef> recipientRefs() {
            return List.of(
                new RecipientRef(
                    "recipient-1",
                    recipient1XKid,
                    recipient1MlKid,
                    Map.of()
                ),
                new RecipientRef(
                    "recipient-2",
                    recipient2XKid,
                    recipient2MlKid,
                    Map.of()
                )
            );
        }

        @Override
        public Optional<RecipientPublicKeyMaterial> resolve(RecipientRef recipient) {
            return switch (recipient.recipientId()) {
                case "recipient-1" -> Optional.of(new RecipientPublicKeyMaterial(
                    recipient1XKid,
                    recipient1XPublic,
                    recipient1MlKid,
                    recipient1MlPublic
                ));
                case "recipient-2" -> Optional.of(new RecipientPublicKeyMaterial(
                    recipient2XKid,
                    recipient2XPublic,
                    recipient2MlKid,
                    recipient2MlPublic
                ));
                default -> Optional.empty();
            };
        }

        @Override
        public Optional<SenderEncryptionKeyLease> open(SenderEncryptionIdentityRef identity) {
            return "sender".equals(identity.identityId())
                ? Optional.of(SenderEncryptionKeyLease.x25519(senderKid, senderX25519))
                : Optional.empty();
        }

        @Override
        public List<DecryptionKeyLease> openAll(RecipientIdentityRef identity) {
            if ("recipient-1".equals(identity.recipientId())) {
                return List.of(DecryptionKeyLease.hybrid(
                    recipient1XKid,
                    recipient1X25519,
                    recipient1MlKid,
                    recipient1MlKem
                ));
            }
            if ("recipient-2".equals(identity.recipientId())) {
                return List.of(DecryptionKeyLease.hybrid(
                    recipient2XKid,
                    recipient2X25519,
                    recipient2MlKid,
                    recipient2MlKem
                ));
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
            return "signer".equals(identity.identityId())
                ? Optional.of(SigningIdentityLease.ed25519("signer", signingKid, signingKey))
                : Optional.empty();
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
            signingKey.close();
            recipient2MlKem.close();
            recipient2X25519.close();
            recipient1MlKem.close();
            recipient1X25519.close();
            senderX25519.close();
            clear(signingPublic);
            clear(recipient2MlPublic);
            clear(recipient2XPublic);
            clear(recipient1MlPublic);
            clear(recipient1XPublic);
            clear(senderPublic);
        }

        private static void clear(byte[] value) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
