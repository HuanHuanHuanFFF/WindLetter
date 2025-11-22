package com.windletter.crypto;

import java.security.SecureRandom;

/**
 * Thin wrapper around SecureRandom to centralize CSPRNG usage.
 * 基于 SecureRandom 的统一随机数封装。
 */
public final class WindRandom {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private WindRandom() {
    }

    public static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        SECURE_RANDOM.nextBytes(out);
        return out;
    }
}
