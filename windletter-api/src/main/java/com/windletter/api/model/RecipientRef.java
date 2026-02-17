package com.windletter.api.model;

import java.util.Map;

/**
 * Sender-side recipient reference.
 *
 * @param recipientId application-level recipient identifier
 * @param x25519Kid X25519 public-key kid (optional)
 * @param mlkem768Kid ML-KEM-768 public-key kid (optional)
 * @param attributes extensible additional info
 */
public record RecipientRef(
    String recipientId,
    String x25519Kid,
    String mlkem768Kid,
    Map<String, String> attributes
) {

    public RecipientRef {
        recipientId = ModelChecks.requireNonBlank(recipientId, "recipientId");
        // Provide at least one identifier usable for key resolution.
        if (ModelChecks.isBlank(x25519Kid) && ModelChecks.isBlank(mlkem768Kid)) {
            throw new IllegalArgumentException("at least one recipient key reference must be provided");
        }
        attributes = ModelChecks.copyMap(attributes);
    }
}
