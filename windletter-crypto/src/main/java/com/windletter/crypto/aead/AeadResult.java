package com.windletter.crypto.aead;

import java.util.Arrays;

/**
 * Holder for AEAD encryption outputs.
 * AEAD 加密输出的承载对象。
 */
public final class AeadResult {
    private final byte[] ciphertext;
    private final byte[] tag;

    public AeadResult(byte[] ciphertext, byte[] tag) {
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        this.tag = Arrays.copyOf(tag, tag.length);
    }

    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public byte[] getTag() {
        return Arrays.copyOf(tag, tag.length);
    }
}
