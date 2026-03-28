package com.windletter.protocol.wire;

/**
 * Sender info for public mode.
 */
public record PublicSenderInfo(String kid) implements SenderInfo {

    public PublicSenderInfo {
        kid = WireChecks.requireNonBlank(kid, "kid");
    }
}

