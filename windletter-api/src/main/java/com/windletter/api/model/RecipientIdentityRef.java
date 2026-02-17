package com.windletter.api.model;

/**
 * Receiver-side identity reference.
 *
 * @param recipientId receiver identity ID
 * @param keySelector optional key selector (for key rotation scenarios)
 */
public record RecipientIdentityRef(String recipientId, String keySelector) {

    public RecipientIdentityRef {
        recipientId = ModelChecks.requireNonBlank(recipientId, "recipientId");
    }
}
