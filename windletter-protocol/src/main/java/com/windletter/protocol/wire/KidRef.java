package com.windletter.protocol.wire;

/**
 * Recipient/sender key reference container in wire payload.
 */
public record KidRef(String x25519, String mlkem768) {
}
