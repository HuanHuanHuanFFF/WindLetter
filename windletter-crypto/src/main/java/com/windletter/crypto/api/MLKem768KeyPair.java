package com.windletter.crypto.api;

import java.util.Arrays;

/**
 * Immutable ML-KEM-768 key-pair container.
 */
public record MLKem768KeyPair(byte[] privateKey, byte[] publicKey) {

    public static final int PRIVATE_KEY_LEN = 2400;
    public static final int PUBLIC_KEY_LEN = 1184;

    public MLKem768KeyPair {
        if (privateKey == null || privateKey.length != PRIVATE_KEY_LEN) {
            throw new IllegalArgumentException("privateKey must be " + PRIVATE_KEY_LEN + " bytes");
        }
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("publicKey must be " + PUBLIC_KEY_LEN + " bytes");
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
