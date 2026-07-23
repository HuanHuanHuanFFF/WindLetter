package com.windletter.crypto.api;

import java.util.Arrays;

/**
 * ML-KEM-768 encapsulation output container.
 */
public record MLKem768Encapsulation(byte[] ciphertext, byte[] sharedSecret) implements AutoCloseable {

    public static final int CIPHERTEXT_LEN = 1088;
    public static final int SHARED_SECRET_LEN = 32;

    public MLKem768Encapsulation {
        if (ciphertext == null || ciphertext.length != CIPHERTEXT_LEN) {
            throw new IllegalArgumentException("ciphertext must be " + CIPHERTEXT_LEN + " bytes");
        }
        if (sharedSecret == null || sharedSecret.length != SHARED_SECRET_LEN) {
            throw new IllegalArgumentException("sharedSecret must be " + SHARED_SECRET_LEN + " bytes");
        }
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        sharedSecret = Arrays.copyOf(sharedSecret, sharedSecret.length);
    }

    @Override
    public byte[] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public byte[] sharedSecret() {
        return Arrays.copyOf(sharedSecret, sharedSecret.length);
    }

    @Override
    public void close() {
        Arrays.fill(sharedSecret, (byte) 0);
    }
}
