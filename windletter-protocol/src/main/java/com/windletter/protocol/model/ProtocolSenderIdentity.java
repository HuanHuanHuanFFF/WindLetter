package com.windletter.protocol.model;

/** Authenticated sender identity exposed after successful signature verification. */
public record ProtocolSenderIdentity(String identityId, String signingKid) {

    public ProtocolSenderIdentity {
        if (identityId == null || identityId.isBlank()) {
            throw new IllegalArgumentException("identityId must be non-blank");
        }
        if (signingKid == null || signingKid.isBlank()) {
            throw new IllegalArgumentException("signingKid must be non-blank");
        }
    }
}
