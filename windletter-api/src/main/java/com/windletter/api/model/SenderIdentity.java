package com.windletter.api.model;

import java.util.Map;

/**
 * Sender identity information optionally returned after signature verification.
 *
 * @param senderId sender identity ID
 * @param signingKid signing kid
 * @param attributes extensible metadata
 */
public record SenderIdentity(String senderId, String signingKid, Map<String, String> attributes) {

    public SenderIdentity {
        senderId = ModelChecks.requireNonBlank(senderId, "senderId");
        signingKid = ModelChecks.requireNonBlank(signingKid, "signingKid");
        attributes = ModelChecks.copyMap(attributes);
    }
}
