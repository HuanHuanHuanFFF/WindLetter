package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * Verification public-key material.
 *
 * @param signingKid signing kid
 * @param ed25519PublicKey Ed25519 public key
 * @param metadata extensible metadata
 */
public record VerificationKeyMaterial(
    String signingKid,
    byte[] ed25519PublicKey,
    Map<String, String> metadata
) {

    public VerificationKeyMaterial {
        signingKid = SpiChecks.requireNonBlank(signingKid, "signingKid");
        if (ed25519PublicKey == null || ed25519PublicKey.length != 32) {
            throw new IllegalArgumentException("ed25519PublicKey must be exactly 32 bytes");
        }
        ed25519PublicKey = Arrays.copyOf(ed25519PublicKey, ed25519PublicKey.length);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] ed25519PublicKey() {
        // Return a copy to avoid external mutation of internal public-key arrays.
        return Arrays.copyOf(ed25519PublicKey, ed25519PublicKey.length);
    }
}
