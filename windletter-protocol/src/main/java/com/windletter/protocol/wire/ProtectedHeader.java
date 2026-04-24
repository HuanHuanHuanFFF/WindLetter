package com.windletter.protocol.wire;

/**
 * Parsed protected header.
 */
public record ProtectedHeader(
        String typ,
        String cty,
        String ver,
        String windMode,
        String enc,
        String keyAlg,
        SenderInfo senderInfo
) {

    public ProtectedHeader {
        typ = WireChecks.requireNonBlank(typ, "typ");
        cty = WireChecks.requireNonBlank(cty, "cty");
        ver = WireChecks.requireNonBlank(ver, "ver");
        windMode = WireChecks.requireNonBlank(windMode, "windMode");
        enc = WireChecks.requireNonBlank(enc, "enc");
        keyAlg = WireChecks.requireNonBlank(keyAlg, "keyAlg");
        senderInfo = WireChecks.requireNonNull(senderInfo, "senderInfo");
    }
}
