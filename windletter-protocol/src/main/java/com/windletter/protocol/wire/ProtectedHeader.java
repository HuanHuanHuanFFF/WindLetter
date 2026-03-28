package com.windletter.protocol.wire;

/**
 * Protected header aggregate: stable core plus mode-specific sender info.
 */
public record ProtectedHeader(ProtectedCore core, SenderInfo senderInfo) {

    public ProtectedHeader {
        core = WireChecks.requireNonNull(core, "core");
        senderInfo = WireChecks.requireNonNull(senderInfo, "senderInfo");
    }
}

