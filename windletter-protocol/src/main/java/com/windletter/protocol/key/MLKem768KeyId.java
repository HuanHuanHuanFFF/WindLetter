package com.windletter.protocol.key;

import com.windletter.protocol.codec.Base64Url;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Key identifier derived directly from a raw FIPS 203 ML-KEM-768 public key.
 */
public final class MLKem768KeyId {

    private static final int PUBLIC_KEY_LENGTH = 1184;

    private MLKem768KeyId() {
    }

    public static String derive(byte[] rawPublicKey) {
        if (rawPublicKey == null || rawPublicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("rawPublicKey must contain exactly 1184 bytes");
        }

        try {
            return Base64Url.encode(
                    MessageDigest.getInstance("SHA-256").digest(rawPublicKey)
            );
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
