package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;
import java.util.List;
import java.util.Map;

/**
 * Sender-side encrypt-and-sign request.
 *
 * @param mode transport mode
 * @param keyAlgProfile key algorithm profile
 * @param armorFormat output armor format, defaults to NONE when null
 * @param payload business payload
 * @param recipients recipient list (non-empty)
 * @param customHeaders optional custom header extensions (placed in payload.meta.ext)
 * @param senderEncryptionIdentity sender encryption identity reference (required)
 * @param senderSigningIdentity signing identity reference (required)
 */
public record EncryptAndSignRequest(
    WindMode mode,
    KeyAlgProfile keyAlgProfile,
    ArmorFormat armorFormat,
    Payload payload,
    List<RecipientRef> recipients,
    Map<String, Object> customHeaders,
    SenderEncryptionIdentityRef senderEncryptionIdentity,
    SigningIdentityRef senderSigningIdentity
) {

    /**
     * Canonical constructor with contract validation and immutable-copy normalization.
     *
     * @throws IllegalArgumentException if required fields are missing or recipients is empty
     */
    public EncryptAndSignRequest {
        mode = ModelChecks.requireNonNull(mode, "mode");
        keyAlgProfile = ModelChecks.requireNonNull(keyAlgProfile, "keyAlgProfile");
        armorFormat = armorFormat == null ? ArmorFormat.NONE : armorFormat;
        payload = ModelChecks.requireNonNull(payload, "payload");
        recipients = ModelChecks.copyNonEmptyList(recipients, "recipients");
        customHeaders = ModelChecks.copyMap(customHeaders);
        senderEncryptionIdentity = ModelChecks.requireNonNull(
            senderEncryptionIdentity,
            "senderEncryptionIdentity"
        );
        senderSigningIdentity = ModelChecks.requireNonNull(senderSigningIdentity, "senderSigningIdentity");
    }
}
