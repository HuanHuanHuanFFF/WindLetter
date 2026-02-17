package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * Sender-side signing identity material.
 *
 * @param identityId business identity ID
 * @param signingKid signing kid
 * @param ed25519PrivateKey Ed25519 private key
 * @param metadata extensible metadata
 */
public record SigningIdentityMaterial(
    String identityId,
    String signingKid,
    byte[] ed25519PrivateKey,
    Map<String, String> metadata
) {

    public SigningIdentityMaterial {
        identityId = SpiChecks.requireNonBlank(identityId, "identityId");
        signingKid = SpiChecks.requireNonBlank(signingKid, "signingKid");
        if (ed25519PrivateKey == null || ed25519PrivateKey.length == 0) {
            throw new IllegalArgumentException("ed25519PrivateKey must not be empty");
        }
        ed25519PrivateKey = Arrays.copyOf(ed25519PrivateKey, ed25519PrivateKey.length);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] ed25519PrivateKey() {
        // Return a copy to avoid external mutation of internal key arrays.
        return Arrays.copyOf(ed25519PrivateKey, ed25519PrivateKey.length);
    }
}
