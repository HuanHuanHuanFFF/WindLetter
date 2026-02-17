package com.windletter.api.model;

/**
 * Sender-side signing identity reference.
 *
 * @param identityId business identity ID
 * @param signingKid optional signing kid hint
 */
public record SigningIdentityRef(String identityId, String signingKid) {

    public SigningIdentityRef {
        identityId = ModelChecks.requireNonBlank(identityId, "identityId");
    }
}
