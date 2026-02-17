package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * Decryption-side key material.
 *
 * @param keyId key identifier
 * @param x25519PrivateKey optional X25519 private key
 * @param mlkem768PrivateKey optional ML-KEM-768 private key
 * @param metadata extensible metadata
 */
public record DecryptionKeyMaterial(
    String keyId,
    byte[] x25519PrivateKey,
    byte[] mlkem768PrivateKey,
    Map<String, String> metadata
) {

    public DecryptionKeyMaterial {
        keyId = SpiChecks.requireNonBlank(keyId, "keyId");
        // Must contain at least one usable private key for decryption.
        if (x25519PrivateKey == null && mlkem768PrivateKey == null) {
            throw new IllegalArgumentException("at least one private key is required");
        }
        x25519PrivateKey = copyNullable(x25519PrivateKey);
        mlkem768PrivateKey = copyNullable(mlkem768PrivateKey);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] x25519PrivateKey() {
        // Return a copy to avoid exposing internal mutable arrays.
        return copyNullable(x25519PrivateKey);
    }

    @Override
    public byte[] mlkem768PrivateKey() {
        // Return a copy to avoid exposing internal mutable arrays.
        return copyNullable(mlkem768PrivateKey);
    }

    private static byte[] copyNullable(byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }
}
