package com.windletter.crypto.api;

import java.util.Arrays;

/**
 * Immutable X25519 key-pair container.
 */
public record X25519KeyPair(byte[] privateKey, byte[] publicKey) {

    public X25519KeyPair {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("privateKey must be 32 bytes");
        }
        if (publicKey == null || publicKey.length != 32) {
            throw new IllegalArgumentException("publicKey must be 32 bytes");
        }
        privateKey = Arrays.copyOf(privateKey, privateKey.length);
        publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public byte[] privateKey() {
        return Arrays.copyOf(privateKey, privateKey.length);
    }

    @Override
    public byte[] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }
}
