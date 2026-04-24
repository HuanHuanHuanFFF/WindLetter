package com.windletter.protocol.wire;

import java.util.Arrays;

/**
 * Sender ephemeral public key from protected.epk in obfuscation mode.
 */
public record Epk(String kty, String crv, byte[] x) implements SenderInfo {

    public Epk {
        kty = WireChecks.requireNonBlank(kty, "kty");
        crv = WireChecks.requireNonBlank(crv, "crv");
        x = WireChecks.copyBytes(x, "x");
    }

    @Override
    public byte[] x() {
        return Arrays.copyOf(x, x.length);
    }
}
