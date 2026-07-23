package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Derives obfuscation-mode X25519 recipient identifiers and KEKs. */
public final class ObfuscationX25519KeyDeriver {

    private static final int X25519_SHARED_SECRET_LENGTH = 32;
    private static final int RID_LENGTH = 16;
    private static final int KEK_LENGTH = 32;
    private static final byte[] HKDF_SALT = "wind".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_RID_INFO = "rid/ecc".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_KEK_INFO =
            "WindLetter v1 KEK | X25519".getBytes(StandardCharsets.UTF_8);

    private final X25519Crypto x25519;
    private final HkdfCrypto hkdf;

    public ObfuscationX25519KeyDeriver(X25519Crypto x25519, HkdfCrypto hkdf) {
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
     * Derives a 16-byte rid/ecc and a 32-byte KEK from one X25519 agreement.
     * The supplied private-key handle is borrowed and remains caller-owned.
     */
    public DerivedMaterial derive(X25519PrivateKeyHandle ownKey, byte[] peerPublicKey) {
        if (ownKey == null) {
            throw new IllegalArgumentException("ownKey must not be null");
        }
        if (peerPublicKey == null || peerPublicKey.length != X25519_SHARED_SECRET_LENGTH) {
            throw new IllegalArgumentException("peerPublicKey must contain exactly 32 bytes");
        }

        byte[] shared = null;
        byte[] ridProviderOutput = null;
        byte[] kekProviderOutput = null;
        try {
            shared = x25519.deriveSharedSecret(ownKey, peerPublicKey.clone());
            requireProviderLength(
                    shared,
                    X25519_SHARED_SECRET_LENGTH,
                    "X25519 provider returned a non-32-byte shared secret"
            );
            rejectAllZeroSharedSecret(shared);

            ridProviderOutput = deriveHkdf(shared, HKDF_RID_INFO, RID_LENGTH);
            requireProviderLength(
                    ridProviderOutput,
                    RID_LENGTH,
                    "HKDF provider returned a non-16-byte rid"
            );
            kekProviderOutput = deriveHkdf(shared, HKDF_KEK_INFO, KEK_LENGTH);
            requireProviderLength(
                    kekProviderOutput,
                    KEK_LENGTH,
                    "HKDF provider returned a non-32-byte KEK"
            );
            return new DerivedMaterial(ridProviderOutput, kekProviderOutput);
        } finally {
            clear(shared);
            clear(ridProviderOutput);
            clear(kekProviderOutput);
        }
    }

    private byte[] deriveHkdf(byte[] shared, byte[] info, int length) {
        try {
            return hkdf.derive(HKDF_SALT.clone(), shared, info.clone(), length);
        } catch (CryptoOperationException e) {
            throw new IllegalStateException("HKDF provider failed", e);
        }
    }

    private static void requireProviderLength(
            byte[] value,
            int expectedLength,
            String message
    ) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalStateException(message);
        }
    }

    private static void rejectAllZeroSharedSecret(byte[] shared) {
        int aggregate = 0;
        for (byte current : shared) {
            aggregate |= current;
        }
        if (aggregate == 0) {
            throw new CryptoOperationException(
                    "failed to derive X25519 shared secret: low-order public key"
            );
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    /** Caller-owned derived material with explicit destruction semantics. */
    public static final class DerivedMaterial implements AutoCloseable {

        private final byte[] rid;
        private final byte[] kek;
        private boolean destroyed;

        private DerivedMaterial(byte[] rid, byte[] kek) {
            requireProviderLength(
                    rid,
                    RID_LENGTH,
                    "HKDF provider returned a non-16-byte rid"
            );
            requireProviderLength(
                    kek,
                    KEK_LENGTH,
                    "HKDF provider returned a non-32-byte KEK"
            );
            this.rid = Arrays.copyOf(rid, rid.length);
            this.kek = Arrays.copyOf(kek, kek.length);
        }

        public byte[] rid() {
            ensureNotDestroyed();
            return Arrays.copyOf(rid, rid.length);
        }

        public byte[] kek() {
            ensureNotDestroyed();
            return Arrays.copyOf(kek, kek.length);
        }

        @Override
        public void close() {
            if (!destroyed) {
                clear(rid);
                clear(kek);
                destroyed = true;
            }
        }

        private void ensureNotDestroyed() {
            if (destroyed) {
                throw new IllegalStateException("derived material is closed");
            }
        }
    }
}
