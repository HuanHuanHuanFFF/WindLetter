package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.api.enums.WindMode;
import com.windletter.api.spi.VerificationKeyMaterial;
import com.windletter.core.error.ErrorCode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Phase6ApiContractTest {

    private static final Payload PAYLOAD = new Payload("application/octet-stream", new byte[] {0, 1}, 2);
    private static final List<RecipientRef> RECIPIENTS = List.of(
        new RecipientRef("recipient", "x-kid", null, Map.of())
    );

    @Test
    void obfuscationEncryptMustNotRequireOrAcceptStaticSenderEncryptionIdentity() {
        assertDoesNotThrow(() -> new EncryptRequest(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519,
            ArmorFormat.NONE,
            PAYLOAD,
            RECIPIENTS,
            Map.of(),
            null
        ));

        assertThrows(IllegalArgumentException.class, () -> new EncryptRequest(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519,
            ArmorFormat.NONE,
            PAYLOAD,
            RECIPIENTS,
            Map.of(),
            new SenderEncryptionIdentityRef("must-not-be-used", null)
        ));
    }

    @Test
    void obfuscationSignedEncryptMustNotRequireOrAcceptStaticSenderEncryptionIdentity() {
        assertDoesNotThrow(() -> new EncryptAndSignRequest(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519,
            ArmorFormat.NONE,
            PAYLOAD,
            RECIPIENTS,
            Map.of(),
            null,
            new SigningIdentityRef("signer", null)
        ));

        assertThrows(IllegalArgumentException.class, () -> new EncryptAndSignRequest(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519,
            ArmorFormat.NONE,
            PAYLOAD,
            RECIPIENTS,
            Map.of(),
            new SenderEncryptionIdentityRef("must-not-be-used", null),
            new SigningIdentityRef("signer", null)
        ));
    }

    @Test
    void verificationMaterialMustContainExactlyOneEd25519PublicKey() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new VerificationKeyMaterial("signing-kid", new byte[31], Map.of())
        );
        assertDoesNotThrow(
            () -> new VerificationKeyMaterial("signing-kid", new byte[32], Map.of())
        );
    }

    @Test
    void decryptResultMustEnforceSuccessAuthenticationShape() {
        assertDoesNotThrow(() -> new DecryptResult(
            DecryptStatus.SUCCESS,
            PAYLOAD,
            null,
            VerificationStatus.UNSIGNED,
            null,
            "11111111-1111-4111-8111-111111111111",
            1L
        ));

        SenderIdentity sender = new SenderIdentity("sender", "signing-kid", Map.of());
        assertDoesNotThrow(() -> new DecryptResult(
            DecryptStatus.SUCCESS,
            PAYLOAD,
            sender,
            VerificationStatus.SIGNED_VALID,
            null,
            "11111111-1111-4111-8111-111111111111",
            1L
        ));

        assertThrows(IllegalArgumentException.class, () -> new DecryptResult(
            DecryptStatus.SUCCESS,
            PAYLOAD,
            sender,
            VerificationStatus.UNSIGNED,
            null,
            "11111111-1111-4111-8111-111111111111",
            1L
        ));
        assertThrows(IllegalArgumentException.class, () -> new DecryptResult(
            DecryptStatus.SUCCESS,
            PAYLOAD,
            null,
            VerificationStatus.SIGNED_VALID,
            null,
            "11111111-1111-4111-8111-111111111111",
            1L
        ));
        assertThrows(IllegalArgumentException.class, () -> new DecryptResult(
            DecryptStatus.SUCCESS,
            PAYLOAD,
            null,
            VerificationStatus.UNSIGNED,
            null,
            null,
            1L
        ));
    }

    @Test
    void decryptResultMustEnforceTwoPublicFailureShapes() {
        assertDoesNotThrow(() -> new DecryptResult(
            DecryptStatus.NOT_FOR_ME,
            null,
            null,
            VerificationStatus.NOT_APPLICABLE,
            ErrorCode.NOT_FOR_ME,
            null,
            null
        ));
        assertDoesNotThrow(() -> new DecryptResult(
            DecryptStatus.INVALID_MESSAGE,
            null,
            null,
            VerificationStatus.FAILED,
            ErrorCode.INVALID_MESSAGE,
            null,
            null
        ));

        assertThrows(IllegalArgumentException.class, () -> new DecryptResult(
            DecryptStatus.INVALID_MESSAGE,
            null,
            null,
            VerificationStatus.FAILED,
            ErrorCode.GCM_AUTH_FAILED,
            null,
            null
        ));
        assertThrows(IllegalArgumentException.class, () -> new DecryptResult(
            DecryptStatus.NOT_FOR_ME,
            null,
            new SenderIdentity("sender", "signing-kid", Map.of()),
            VerificationStatus.NOT_APPLICABLE,
            ErrorCode.NOT_FOR_ME,
            null,
            null
        ));
    }
}
