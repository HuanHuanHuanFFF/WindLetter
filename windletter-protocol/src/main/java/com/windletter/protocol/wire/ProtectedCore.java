package com.windletter.protocol.wire;

/**
 * Stable protected core fields.
 */
public record ProtectedCore(
        String typ,
        String cty,
        String ver,
        String windMode,
        String enc,
        String keyAlg
) {

    public ProtectedCore {
        typ = WireChecks.requireNonBlank(typ, "typ");
        cty = WireChecks.requireNonBlank(cty, "cty");
        ver = WireChecks.requireNonBlank(ver, "ver");
        windMode = WireChecks.requireNonBlank(windMode, "windMode");
        enc = WireChecks.requireNonBlank(enc, "enc");
        keyAlg = WireChecks.requireNonBlank(keyAlg, "keyAlg");
    }
}

