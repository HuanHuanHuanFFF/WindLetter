package com.windletter.api.model;

/**
 * Sender-side encryption identity reference.
 *
 * @param identityId business identity ID
 * @param keySelector optional selector for an encryption-key version or alias
 */
public record SenderEncryptionIdentityRef(String identityId, String keySelector) {

    public SenderEncryptionIdentityRef {
        identityId = ModelChecks.requireNonBlank(identityId, "identityId");
    }
}
