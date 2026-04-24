package com.windletter.protocol.wire;

/**
 * Sender kid from protected.kid in public mode.
 */
public record SenderKid(String x25519) implements SenderInfo {

    public SenderKid {
        x25519 = WireChecks.requireNonBlank(x25519, "x25519");
    }
}
