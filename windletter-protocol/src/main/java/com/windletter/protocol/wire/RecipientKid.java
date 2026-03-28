package com.windletter.protocol.wire;

/**
 * Recipient kid fields in public mode.
 */
public record RecipientKid(String x25519Kid, String mlkem768Kid) {
}

