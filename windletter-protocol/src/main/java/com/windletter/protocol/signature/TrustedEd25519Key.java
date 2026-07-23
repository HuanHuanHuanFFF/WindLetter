package com.windletter.protocol.signature;

import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.codec.Base64Url;

import java.util.Arrays;

/** Trusted sender identity and its Ed25519 verification key. */
public record TrustedEd25519Key(String identityId, String signingKid, byte[] publicKey) {

    private static final int KEY_LENGTH = 32;

    public TrustedEd25519Key {
        if (identityId == null || identityId.isBlank()) {
            throw new IllegalArgumentException("identityId must be non-blank");
        }
        if (signingKid == null || signingKid.isBlank()) {
            throw new IllegalArgumentException("signingKid must be non-blank");
        }

        byte[] decodedKid;
        try {
            decodedKid = Base64Url.decodeCanonical(signingKid, "signingKid");
        } catch (ProtocolException e) {
            throw new IllegalArgumentException("signingKid must be canonical Base64URL", e);
        }
        if (decodedKid.length != KEY_LENGTH) {
            throw new IllegalArgumentException("signingKid must decode to exactly 32 bytes");
        }
        if (publicKey == null || publicKey.length != KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey must contain exactly 32 bytes");
        }
        publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public byte[] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }
}
