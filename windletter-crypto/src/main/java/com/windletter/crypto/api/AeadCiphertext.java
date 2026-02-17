package com.windletter.crypto.api;

import java.util.Arrays;

/**
 * AEAD encryption output container.
 *
 * @param ciphertext ciphertext bytes
 * @param tag authentication tag (16 bytes for GCM)
 */
public record AeadCiphertext(byte[] ciphertext, byte[] tag) {

    public AeadCiphertext {
        if (ciphertext == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }
        if (tag == null || tag.length != 16) {
            throw new IllegalArgumentException("tag must be 16 bytes");
        }
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        tag = Arrays.copyOf(tag, tag.length);
    }

    @Override
    public byte[] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public byte[] tag() {
        return Arrays.copyOf(tag, tag.length);
    }
}
