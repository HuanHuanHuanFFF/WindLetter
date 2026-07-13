package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Derives the public-mode X25519 KEK defined by Wind Letter v1.0.
 */
public final class PublicX25519KekDeriver {

    private static final int X25519_LENGTH = 32;
    private static final int KEK_LENGTH = 32;
    private static final byte[] HKDF_SALT = "wind".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO =
            "WindLetter v1 KEK | X25519".getBytes(StandardCharsets.UTF_8);

    private final X25519Crypto x25519;
    private final HkdfCrypto hkdf;

    public PublicX25519KekDeriver(X25519Crypto x25519, HkdfCrypto hkdf) {
        if (x25519 == null) {
            throw new IllegalArgumentException("x25519 must not be null");
        }
        if (hkdf == null) {
            throw new IllegalArgumentException("hkdf must not be null");
        }
        this.x25519 = x25519;
        this.hkdf = hkdf;
    }

    /**
     * Derives a 32-byte KEK. The supplied private-key handle is borrowed and remains caller-owned.
     */
    public byte[] derive(X25519PrivateKeyHandle ownKey, byte[] peerPublicKey) {
        if (ownKey == null) {
            throw new IllegalArgumentException("ownKey must not be null");
        }
        if (peerPublicKey == null || peerPublicKey.length != X25519_LENGTH) {
            throw new IllegalArgumentException("peerPublicKey must contain exactly 32 bytes");
        }

        byte[] shared = null;
        try {
            shared = x25519.deriveSharedSecret(ownKey, peerPublicKey.clone());
            if (shared == null || shared.length != X25519_LENGTH) {
                throw new IllegalStateException("X25519 provider returned a non-32-byte shared secret");
            }
            if (isAllZero(shared)) {
                throw new CryptoOperationException("failed to derive X25519 shared secret: low-order public key");
            }

            byte[] kek = hkdf.derive(
                    HKDF_SALT.clone(),
                    shared,
                    HKDF_INFO.clone(),
                    KEK_LENGTH
            );
            if (kek == null || kek.length != KEK_LENGTH) {
                if (kek != null) {
                    Arrays.fill(kek, (byte) 0);
                }
                throw new IllegalStateException("HKDF provider returned a non-32-byte KEK");
            }
            return kek;
        } finally {
            if (shared != null) {
                Arrays.fill(shared, (byte) 0);
            }
        }
    }

    private static boolean isAllZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }
}
