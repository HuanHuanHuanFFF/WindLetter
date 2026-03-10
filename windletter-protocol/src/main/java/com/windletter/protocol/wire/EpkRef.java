package com.windletter.protocol.wire;

/**
 * Ephemeral X25519 public key reference for obfuscation mode.
 */
public record EpkRef(String kty, String crv, String x) {
}
