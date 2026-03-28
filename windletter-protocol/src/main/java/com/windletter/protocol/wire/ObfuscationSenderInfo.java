package com.windletter.protocol.wire;

import java.util.Arrays;

/**
 * Sender info for obfuscation mode.
 */
public record ObfuscationSenderInfo(String kty, String crv, byte[] epkX) implements SenderInfo {

    public ObfuscationSenderInfo {
        kty = WireChecks.requireNonBlank(kty, "kty");
        crv = WireChecks.requireNonBlank(crv, "crv");
        epkX = WireChecks.copyBytes(epkX, "epkX");
    }

    @Override
    public byte[] epkX() {
        return Arrays.copyOf(epkX, epkX.length);
    }
}

