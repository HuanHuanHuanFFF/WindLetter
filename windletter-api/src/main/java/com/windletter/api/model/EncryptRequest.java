package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;

import java.util.List;
import java.util.Map;

/**
 * Sender-side encryption request (without signing identity).
 *
 * @param mode transport mode
 * @param keyAlgProfile key algorithm profile
 * @param armorFormat output armor format, defaults to NONE when null
 * @param payload business payload
 * @param recipients recipient list (non-empty)
 * @param customHeaders optional custom header extensions
 * @param senderEncryptionIdentity sender encryption identity reference; required for public and forbidden for obfuscation
 */
public record EncryptRequest(
    WindMode mode,
    KeyAlgProfile keyAlgProfile,
    ArmorFormat armorFormat,
    Payload payload,
    List<RecipientRef> recipients,
    Map<String, Object> customHeaders,
    SenderEncryptionIdentityRef senderEncryptionIdentity
) {

    /**
     * Canonical constructor with contract validation and immutable-copy normalization.
     *
     * @throws IllegalArgumentException if required fields are missing or recipients is empty
     */
    public EncryptRequest {
        mode = ModelChecks.requireNonNull(mode, "mode");
        keyAlgProfile = ModelChecks.requireNonNull(keyAlgProfile, "keyAlgProfile");
        armorFormat = armorFormat == null ? ArmorFormat.NONE : armorFormat;
        payload = ModelChecks.requireNonNull(payload, "payload");
        // Freeze immutable views to avoid later caller-side mutations affecting this request object.
        recipients = ModelChecks.copyNonEmptyList(recipients, "recipients");
        customHeaders = ModelChecks.copyMap(customHeaders);
        if (mode == WindMode.PUBLIC) {
            senderEncryptionIdentity = ModelChecks.requireNonNull(
                senderEncryptionIdentity,
                "senderEncryptionIdentity"
            );
        } else if (senderEncryptionIdentity != null) {
            throw new IllegalArgumentException(
                "senderEncryptionIdentity must be null when mode is OBFUSCATION"
            );
        }
    }
}
