package com.windletter.api.spi;

import java.util.Arrays;

/**
 * Recipient public-key material for the currently defined key profiles.
 *
 * @param x25519Kid X25519 key identifier
 * @param x25519PublicKey exactly 32 bytes of X25519 public-key material
 * @param mlkem768Kid optional ML-KEM-768 key identifier
 * @param mlkem768PublicKey optional, exactly 1184 bytes when present
 */
public record RecipientPublicKeyMaterial(
    String x25519Kid,
    byte[] x25519PublicKey,
    String mlkem768Kid,
    byte[] mlkem768PublicKey
) {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;

    public RecipientPublicKeyMaterial {
        x25519Kid = SpiChecks.requireNonBlank(x25519Kid, "x25519Kid");
        if (x25519PublicKey == null || x25519PublicKey.length != X25519_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("x25519PublicKey must be exactly 32 bytes");
        }

        boolean mlkem768KidAbsent = mlkem768Kid == null;
        boolean mlkem768PublicKeyAbsent = mlkem768PublicKey == null;
        if (mlkem768KidAbsent != mlkem768PublicKeyAbsent) {
            throw new IllegalArgumentException("ML-KEM-768 kid and public key must both be present or absent");
        }
        if (!mlkem768KidAbsent) {
            mlkem768Kid = SpiChecks.requireNonBlank(mlkem768Kid, "mlkem768Kid");
            if (mlkem768PublicKey.length != MLKEM768_PUBLIC_KEY_LENGTH) {
                throw new IllegalArgumentException("mlkem768PublicKey must be exactly 1184 bytes");
            }
            mlkem768PublicKey = Arrays.copyOf(mlkem768PublicKey, mlkem768PublicKey.length);
        }

        x25519PublicKey = Arrays.copyOf(x25519PublicKey, x25519PublicKey.length);
    }

    @Override
    public byte[] x25519PublicKey() {
        return Arrays.copyOf(x25519PublicKey, x25519PublicKey.length);
    }

    @Override
    public byte[] mlkem768PublicKey() {
        return mlkem768PublicKey == null
            ? null
            : Arrays.copyOf(mlkem768PublicKey, mlkem768PublicKey.length);
    }
}
