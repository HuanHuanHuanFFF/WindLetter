package com.windletter.protocol.wire;

/**
 * Recipient key identifier references in transport form.
 */
public record KidRef(
    String x25519,
    String mlkem768
) {
}
