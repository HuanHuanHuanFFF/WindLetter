package com.windletter.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.WindLetter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class WindLetterEightProfileApiE2ETest {

    private static final List<PayloadCase> PAYLOADS = List.of(
        new PayloadCase(
            "text",
            "text/plain;charset=UTF-8",
            "Wind Letter API matrix".getBytes(StandardCharsets.UTF_8)
        ),
        new PayloadCase(
            "binary",
            "application/octet-stream",
            new byte[] {0, (byte) 0xff, 7, 0, (byte) 0x80}
        )
    );

    @TestFactory
    Stream<DynamicTest> allEightProfilesRoundTripTextAndBinaryThroughPublicApi() {
        return Stream.of(WindMode.PUBLIC, WindMode.OBFUSCATION)
            .flatMap(mode -> Stream.of(
                KeyAlgProfile.X25519,
                KeyAlgProfile.X25519_ML_KEM_768
            ).flatMap(profile -> Stream.of(false, true)
                .flatMap(signed -> Stream.of(ArmorFormat.values())
                    .flatMap(format -> PAYLOADS.stream().map(payloadCase -> DynamicTest.dynamicTest(
                        mode + "/" + profile + "/" + (signed ? "signed" : "unsigned")
                            + "/" + format + "/" + payloadCase.name(),
                        () -> roundTrip(mode, profile, signed, format, payloadCase)
                    ))))));
    }

    @Test
    void textArmorCanBeAutoDetected() {
        for (ArmorFormat format : List.of(
            ArmorFormat.BASE64_PEM,
            ArmorFormat.WIND_BASE_1024F_V1
        )) {
            try (Fixture keys = new Fixture(KeyAlgProfile.X25519)) {
                EncryptedMessage encrypted = encryptUnsigned(
                    WindMode.PUBLIC,
                    KeyAlgProfile.X25519,
                    format,
                    keys
                );
                WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
                DecryptResult result = receiver.decrypt(new DecryptRequest(
                    null,
                    encrypted.armor(),
                    null,
                    null,
                    new RecipientIdentityRef("recipient-2", null),
                    VerificationPolicy.AUTO_BY_CTY
                ));

                assertEquals(DecryptStatus.SUCCESS, result.status());
            }
        }
    }

    @Test
    void malformedArmorIsRejectedBeforeRecipientKeysAreOpened() {
        try (Fixture keys = new Fixture(KeyAlgProfile.X25519)) {
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(new DecryptRequest(
                null,
                null,
                new byte[] {0, 1, 2},
                ArmorFormat.BINARY,
                new RecipientIdentityRef("recipient-2", null),
                VerificationPolicy.AUTO_BY_CTY
            ));

            assertGenericInvalid(result);
            assertEquals(0, keys.recipientLeaseOpens);
        }
    }

    @TestFactory
    Stream<DynamicTest> allReceiverProfilesReturnNotForMeAndCloseUnrelatedLeases() {
        return Stream.of(WindMode.PUBLIC, WindMode.OBFUSCATION)
            .flatMap(mode -> Stream.of(
                KeyAlgProfile.X25519,
                KeyAlgProfile.X25519_ML_KEM_768
            ).map(profile -> DynamicTest.dynamicTest(
                mode + "/" + profile + "/not-for-me",
                () -> notForMe(mode, profile)
            )));
    }

    @TestFactory
    Stream<DynamicTest> allReceiverProfilesHideCiphertextFailureAndCloseMatchingLeases() {
        return Stream.of(WindMode.PUBLIC, WindMode.OBFUSCATION)
            .flatMap(mode -> Stream.of(
                KeyAlgProfile.X25519,
                KeyAlgProfile.X25519_ML_KEM_768
            ).map(profile -> DynamicTest.dynamicTest(
                mode + "/" + profile + "/invalid-ciphertext",
                () -> invalidCiphertext(mode, profile)
            )));
    }

    private static void notForMe(WindMode mode, KeyAlgProfile profile) {
        try (Fixture keys = new Fixture(profile)) {
            EncryptedMessage encrypted = encryptUnsigned(mode, profile, keys);
            X25519PrivateKeyHandle unrelatedX = keys.x25519.generatePrivateKey();
            MLKem768PrivateKeyHandle unrelatedMl = profile == KeyAlgProfile.X25519_ML_KEM_768
                ? keys.mlkem.generatePrivateKey()
                : null;
            byte[] xPublic = unrelatedX.publicKey();
            byte[] mlPublic = unrelatedMl == null ? null : unrelatedMl.publicKey();
            String xKid = X25519KeyId.derive(xPublic);
            String mlKid = mlPublic == null ? null : MLKem768KeyId.derive(mlPublic);
            clear(xPublic);
            clear(mlPublic);
            RecipientKeyStore unrelatedStore = identity -> profile == KeyAlgProfile.X25519
                ? List.of(DecryptionKeyLease.x25519(xKid, unrelatedX))
                : List.of(DecryptionKeyLease.hybrid(
                    xKid,
                    unrelatedX,
                    mlKid,
                    unrelatedMl
                ));
            try {
                WindLetterReceiver receiver = WindLetterRuntime.receiver(
                    unrelatedStore,
                    keys,
                    keys
                );
                DecryptResult result = receiver.decrypt(decryptRequest(encrypted.wireJson()));
                assertNotForMe(result);
                assertClosed(unrelatedX);
                if (unrelatedMl != null) {
                    assertClosed(unrelatedMl);
                }
            } finally {
                unrelatedX.close();
                if (unrelatedMl != null) {
                    unrelatedMl.close();
                }
            }
        }
    }

    private static void invalidCiphertext(WindMode mode, KeyAlgProfile profile) {
        try (Fixture keys = new Fixture(profile)) {
            EncryptedMessage encrypted = encryptUnsigned(mode, profile, keys);
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(decryptRequest(
                flipCiphertext(encrypted.wireJson())
            ));

            assertGenericInvalid(result);
            assertClosed(keys.recipient2X25519);
            if (profile == KeyAlgProfile.X25519_ML_KEM_768) {
                assertClosed(keys.recipient2MlKem);
            }
            assertEquals(0, keys.verificationLookups);
            assertEquals(0, keys.identityLookups);
        }
    }

    private static EncryptedMessage encryptUnsigned(
        WindMode mode,
        KeyAlgProfile profile,
        Fixture keys
    ) {
        return encryptUnsigned(mode, profile, ArmorFormat.NONE, keys);
    }

    private static EncryptedMessage encryptUnsigned(
        WindMode mode,
        KeyAlgProfile profile,
        ArmorFormat armorFormat,
        Fixture keys
    ) {
        WindLetterSender sender = WindLetterRuntime.sender(keys, keys, keys);
        return sender.encrypt(new EncryptRequest(
            mode,
            profile,
            armorFormat,
            new Payload("application/octet-stream", new byte[] {0, 1, 2}, 3),
            keys.recipientRefs(),
            Map.of(),
            mode == WindMode.PUBLIC
                ? new SenderEncryptionIdentityRef("sender", keys.senderKid)
                : null
        ));
    }

    private static DecryptRequest decryptRequest(String wireJson) {
        return new DecryptRequest(
            wireJson,
            null,
            null,
            ArmorFormat.NONE,
            new RecipientIdentityRef("recipient-2", null),
            VerificationPolicy.AUTO_BY_CTY
        );
    }

    private static String flipCiphertext(String wireJson) {
        WindLetter letter = new JacksonOuterWireParser().parse(wireJson);
        byte[] ciphertext = letter.ciphertext();
        try {
            ciphertext[0] ^= 1;
            return new JacksonOuterWireWriter().write(new WindLetter(
                letter.protectedHeader(),
                letter.protectedValue(),
                letter.aad(),
                letter.recipients(),
                letter.iv(),
                ciphertext,
                letter.tag()
            ));
        } finally {
            clear(ciphertext);
        }
    }

    private static void assertNotForMe(DecryptResult result) {
        assertEquals(DecryptStatus.NOT_FOR_ME, result.status());
        assertEquals(VerificationStatus.NOT_APPLICABLE, result.verificationStatus());
        assertEquals(ErrorCode.NOT_FOR_ME, result.errorCode());
        assertNull(result.payload());
        assertNull(result.senderIdentity());
        assertNull(result.messageId());
        assertNull(result.timestamp());
    }

    private static void assertGenericInvalid(DecryptResult result) {
        assertEquals(DecryptStatus.INVALID_MESSAGE, result.status());
        assertEquals(VerificationStatus.FAILED, result.verificationStatus());
        assertEquals(ErrorCode.INVALID_MESSAGE, result.errorCode());
        assertNull(result.payload());
        assertNull(result.senderIdentity());
        assertNull(result.messageId());
        assertNull(result.timestamp());
    }

    private static void roundTrip(
        WindMode mode,
        KeyAlgProfile profile,
        boolean signed,
        ArmorFormat armorFormat,
        PayloadCase payloadCase
    ) {
        try (Fixture keys = new Fixture(profile)) {
            WindLetterSender sender = WindLetterRuntime.sender(keys, keys, keys);
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            Payload payload = new Payload(
                payloadCase.contentType(),
                payloadCase.data(),
                payloadCase.data().length
            );
            SenderEncryptionIdentityRef senderEncryption = mode == WindMode.PUBLIC
                ? new SenderEncryptionIdentityRef("sender", keys.senderKid)
                : null;

            EncryptedMessage encrypted = signed
                ? sender.encryptAndSign(new EncryptAndSignRequest(
                    mode,
                    profile,
                    armorFormat,
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption,
                    new SigningIdentityRef("signer", keys.signingKid)
                ))
                : sender.encrypt(new EncryptRequest(
                    mode,
                    profile,
                    armorFormat,
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption
                ));

            var parsed = new JacksonOuterWireParser().parse(encrypted.wireJson());
            assertEquals(mode == WindMode.PUBLIC ? "public" : "obfuscation",
                parsed.protectedHeader().windMode());
            assertEquals(profile == KeyAlgProfile.X25519
                    ? "X25519"
                    : "X25519ML-KEM-768",
                parsed.protectedHeader().keyAlg());
            assertEquals(signed ? "wind+jws" : "wind+inner",
                parsed.protectedHeader().cty());

            DecryptResult result = receiver.decrypt(decryptRequest(encrypted));

            assertEquals(DecryptStatus.SUCCESS, result.status());
            assertEquals(payload.contentType(), result.payload().contentType());
            assertArrayEquals(payload.data(), result.payload().data());
            assertEquals(payload.originalSize(), result.payload().originalSize());
            assertEquals(signed
                    ? VerificationStatus.SIGNED_VALID
                    : VerificationStatus.UNSIGNED,
                result.verificationStatus());
            if (signed) {
                assertEquals(keys.trustedSender(), result.senderIdentity());
                assertTrue(keys.verificationLookups > 0);
                assertTrue(keys.identityLookups > 0);
                assertClosed(keys.signingKey);
            } else {
                assertNull(result.senderIdentity());
                assertEquals(0, keys.verificationLookups);
                assertEquals(0, keys.identityLookups);
            }

            assertEquals(1, keys.recipientLeaseOpens);
            assertClosed(keys.recipient2X25519);
            if (profile == KeyAlgProfile.X25519_ML_KEM_768) {
                assertClosed(keys.recipient2MlKem);
            }
            if (mode == WindMode.PUBLIC) {
                assertEquals(1, keys.senderEncryptionOpens);
                assertTrue(keys.senderPublicLookups > 0);
                assertClosed(keys.senderX25519);
            } else {
                assertEquals(0, keys.senderEncryptionOpens);
                assertEquals(0, keys.senderPublicLookups);
                byte[] stillOpen = keys.senderX25519.publicKey();
                clear(stillOpen);
            }
        }
    }

    private static DecryptRequest decryptRequest(EncryptedMessage encrypted) {
        return new DecryptRequest(
            encrypted.armorFormat() == ArmorFormat.NONE ? encrypted.wireJson() : null,
            encrypted.armor(),
            encrypted.armorBytes(),
            encrypted.armorFormat(),
            new RecipientIdentityRef("recipient-2", null),
            VerificationPolicy.AUTO_BY_CTY
        );
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

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record PayloadCase(String name, String contentType, byte[] data) {
        private PayloadCase {
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }
    }

    private static final class Fixture implements
        RecipientPublicKeyResolver,
        SenderEncryptionKeyStore,
        RecipientKeyStore,
        SenderPublicKeyResolver,
        IdentityService,
        AutoCloseable {

        private final KeyAlgProfile profile;
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

        private int senderEncryptionOpens;
        private int senderPublicLookups;
        private int recipientLeaseOpens;
        private int verificationLookups;
        private int identityLookups;

        private Fixture(KeyAlgProfile profile) {
            this.profile = profile;
        }

        private List<RecipientRef> recipientRefs() {
            if (profile == KeyAlgProfile.X25519) {
                return List.of(
                    new RecipientRef("recipient-1", recipient1XKid, null, Map.of()),
                    new RecipientRef("recipient-2", recipient2XKid, null, Map.of())
                );
            }
            return List.of(
                new RecipientRef(
                    "recipient-1",
                    recipient1XKid,
                    recipient1MlKid,
                    Map.of()
                ),
                new RecipientRef("recipient-2", null, recipient2MlKid, Map.of())
            );
        }

        private SenderIdentity trustedSender() {
            return new SenderIdentity(
                "trusted-sender",
                signingKid,
                Map.of("matrix", "true")
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
            senderEncryptionOpens++;
            return "sender".equals(identity.identityId())
                ? Optional.of(SenderEncryptionKeyLease.x25519(senderKid, senderX25519))
                : Optional.empty();
        }

        @Override
        public List<DecryptionKeyLease> openAll(RecipientIdentityRef identity) {
            recipientLeaseOpens++;
            if (!"recipient-2".equals(identity.recipientId())) {
                return List.of();
            }
            return profile == KeyAlgProfile.X25519
                ? List.of(DecryptionKeyLease.x25519(recipient2XKid, recipient2X25519))
                : List.of(DecryptionKeyLease.hybrid(
                    recipient2XKid,
                    recipient2X25519,
                    recipient2MlKid,
                    recipient2MlKem
                ));
        }

        @Override
        public Optional<X25519PublicKeyMaterial> resolveX25519ByKid(String kid) {
            senderPublicLookups++;
            return senderKid.equals(kid)
                ? Optional.of(new X25519PublicKeyMaterial(senderKid, senderPublic))
                : Optional.empty();
        }

        @Override
        public Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef identity) {
            return "signer".equals(identity.identityId())
                ? Optional.of(SigningIdentityLease.ed25519(
                    "signer",
                    signingKid,
                    signingKey
                ))
                : Optional.empty();
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
                ? Optional.of(trustedSender())
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
    }
}
