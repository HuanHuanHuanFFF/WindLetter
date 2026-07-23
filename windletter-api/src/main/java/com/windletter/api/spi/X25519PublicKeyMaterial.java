package com.windletter.api.spi;

import java.util.Arrays;

/**
 * X25519 public-key material.
 *
 * @param kid key identifier
 * @param publicKey exactly 32 bytes of X25519 public-key material
 */
public record X25519PublicKeyMaterial(String kid, byte[] publicKey) {

    private static final int PUBLIC_KEY_LENGTH = 32;

    public X25519PublicKeyMaterial {
        kid = SpiChecks.requireNonBlank(kid, "kid");
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey must be exactly 32 bytes");
        }
        publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public byte[] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }
}
