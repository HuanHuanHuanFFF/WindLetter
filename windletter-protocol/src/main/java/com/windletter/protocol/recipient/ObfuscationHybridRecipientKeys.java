package com.windletter.protocol.recipient;

import java.util.Arrays;

/** Atomic X25519/ML-KEM-768 public-key pair for one obfuscation recipient. */
public record ObfuscationHybridRecipientKeys(
        byte[] x25519PublicKey,
        byte[] mlkem768PublicKey
) {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;

    public ObfuscationHybridRecipientKeys {
        requireLength(x25519PublicKey, X25519_PUBLIC_KEY_LENGTH, "x25519PublicKey");
        requireLength(mlkem768PublicKey, MLKEM768_PUBLIC_KEY_LENGTH, "mlkem768PublicKey");
        x25519PublicKey = Arrays.copyOf(x25519PublicKey, x25519PublicKey.length);
        mlkem768PublicKey = Arrays.copyOf(mlkem768PublicKey, mlkem768PublicKey.length);
    }

    @Override
    public byte[] x25519PublicKey() {
        return Arrays.copyOf(x25519PublicKey, x25519PublicKey.length);
    }

    @Override
    public byte[] mlkem768PublicKey() {
        return Arrays.copyOf(mlkem768PublicKey, mlkem768PublicKey.length);
    }

    private static void requireLength(byte[] value, int expectedLength, String name) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalArgumentException(
                    name + " must contain exactly " + expectedLength + " bytes"
            );
        }
    }
}
