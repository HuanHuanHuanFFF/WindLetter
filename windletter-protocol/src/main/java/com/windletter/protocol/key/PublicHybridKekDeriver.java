package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Derives public-mode X25519/ML-KEM-768 hybrid KEKs. */
public final class PublicHybridKekDeriver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;
    private static final int SHARED_SECRET_LENGTH = 32;
    private static final int ENCAPSULATION_CIPHERTEXT_LENGTH = 1088;
    private static final int KEK_LENGTH = 32;
    private static final byte[] HKDF_SALT = "wind".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO =
            "WindLetter v1 KEK | X25519ML-KEM-768".getBytes(StandardCharsets.UTF_8);

    private final X25519Crypto x25519;
    private final MLKem768Crypto mlkem768;
    private final HkdfCrypto hkdf;

    public PublicHybridKekDeriver(
            X25519Crypto x25519,
            MLKem768Crypto mlkem768,
            HkdfCrypto hkdf
    ) {
        if (x25519 == null) {
            throw new IllegalArgumentException("x25519 must not be null");
        }
        if (mlkem768 == null) {
            throw new IllegalArgumentException("mlkem768 must not be null");
        }
        if (hkdf == null) {
            throw new IllegalArgumentException("hkdf must not be null");
        }
        this.x25519 = x25519;
        this.mlkem768 = mlkem768;
        this.hkdf = hkdf;
    }

    /**
     * Derives a recipient-specific KEK and ML-KEM ciphertext for a sender.
     * The supplied X25519 private-key handle is borrowed and remains caller-owned.
     */
    public SenderDerivation deriveForSender(
            X25519PrivateKeyHandle senderX25519PrivateKey,
            byte[] recipientX25519PublicKey,
            byte[] recipientMlkem768PublicKey
    ) {
        requireHandle(senderX25519PrivateKey, "senderX25519PrivateKey");
        requireLength(
                recipientX25519PublicKey,
                X25519_PUBLIC_KEY_LENGTH,
                "recipientX25519PublicKey"
        );
        requireLength(
                recipientMlkem768PublicKey,
                MLKEM768_PUBLIC_KEY_LENGTH,
                "recipientMlkem768PublicKey"
        );

        byte[] ssEcc = null;
        byte[] ssPq = null;
        byte[] encapsulationCiphertext = null;
        byte[] kek = null;
        try {
            ssEcc = x25519.deriveSharedSecret(
                    senderX25519PrivateKey,
                    recipientX25519PublicKey.clone()
            );
            requireProviderSecret(ssEcc, "X25519");
            rejectAllZeroX25519(ssEcc);

            MLKem768Encapsulation encapsulation =
                    mlkem768.encapsulate(recipientMlkem768PublicKey.clone());
            if (encapsulation == null) {
                throw new IllegalStateException("ML-KEM provider returned a null encapsulation");
            }
            try (encapsulation) {
                encapsulationCiphertext = encapsulation.ciphertext();
                requireProviderLength(
                        encapsulationCiphertext,
                        ENCAPSULATION_CIPHERTEXT_LENGTH,
                        "ML-KEM encapsulation ciphertext"
                );
                ssPq = encapsulation.sharedSecret();
                requireProviderSecret(ssPq, "ML-KEM");

                kek = deriveCombined(hkdf, ssEcc, ssPq);
                return new SenderDerivation(kek, encapsulationCiphertext);
            }
        } finally {
            clear(ssEcc);
            clear(ssPq);
            clear(kek);
            clear(encapsulationCiphertext);
        }
    }

    /**
     * Derives the matching recipient KEK. Both private-key handles are borrowed.
     */
    public byte[] deriveForReceiver(
            X25519PrivateKeyHandle recipientX25519PrivateKey,
            byte[] senderX25519PublicKey,
            MLKem768PrivateKeyHandle recipientMlkem768PrivateKey,
            byte[] encapsulationCiphertext
    ) {
        requireHandle(recipientX25519PrivateKey, "recipientX25519PrivateKey");
        requireLength(senderX25519PublicKey, X25519_PUBLIC_KEY_LENGTH, "senderX25519PublicKey");
        requireHandle(recipientMlkem768PrivateKey, "recipientMlkem768PrivateKey");
        requireLength(
                encapsulationCiphertext,
                ENCAPSULATION_CIPHERTEXT_LENGTH,
                "encapsulationCiphertext"
        );

        byte[] ssEcc = null;
        byte[] ssPq = null;
        try {
            ssEcc = x25519.deriveSharedSecret(
                    recipientX25519PrivateKey,
                    senderX25519PublicKey.clone()
            );
            requireProviderSecret(ssEcc, "X25519");
            rejectAllZeroX25519(ssEcc);

            ssPq = mlkem768.decapsulate(
                    recipientMlkem768PrivateKey,
                    encapsulationCiphertext.clone()
            );
            requireProviderSecret(ssPq, "ML-KEM");
            return deriveCombined(hkdf, ssEcc, ssPq);
        } finally {
            clear(ssEcc);
            clear(ssPq);
        }
    }

    static byte[] deriveCombined(HkdfCrypto hkdf, byte[] ssEcc, byte[] ssPq) {
        if (hkdf == null) {
            throw new IllegalArgumentException("hkdf must not be null");
        }
        requireLength(ssEcc, SHARED_SECRET_LENGTH, "ssEcc");
        requireLength(ssPq, SHARED_SECRET_LENGTH, "ssPq");

        byte[] z = new byte[SHARED_SECRET_LENGTH * 2];
        System.arraycopy(ssEcc, 0, z, 0, SHARED_SECRET_LENGTH);
        System.arraycopy(ssPq, 0, z, SHARED_SECRET_LENGTH, SHARED_SECRET_LENGTH);
        try {
            byte[] kek = hkdf.derive(HKDF_SALT.clone(), z, HKDF_INFO.clone(), KEK_LENGTH);
            if (kek == null || kek.length != KEK_LENGTH) {
                clear(kek);
                throw new IllegalStateException("HKDF provider returned a non-32-byte KEK");
            }
            return kek;
        } catch (CryptoOperationException e) {
            throw new IllegalStateException("HKDF provider failed", e);
        } finally {
            clear(z);
        }
    }

    private static void requireHandle(Object handle, String name) {
        if (handle == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
    }

    private static void requireLength(byte[] value, int expectedLength, String name) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalArgumentException(
                    name + " must contain exactly " + expectedLength + " bytes"
            );
        }
    }

    private static void requireProviderSecret(byte[] value, String algorithm) {
        if (value == null || value.length != SHARED_SECRET_LENGTH) {
            clear(value);
            throw new IllegalStateException(
                    algorithm + " provider returned a non-32-byte shared secret"
            );
        }
    }

    private static void requireProviderLength(
            byte[] value,
            int expectedLength,
            String description
    ) {
        if (value == null || value.length != expectedLength) {
            clear(value);
            throw new IllegalStateException(
                    description + " must contain exactly " + expectedLength + " bytes"
            );
        }
    }

    private static void rejectAllZeroX25519(byte[] sharedSecret) {
        int aggregate = 0;
        for (byte current : sharedSecret) {
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

    public record SenderDerivation(byte[] kek, byte[] encapsulationCiphertext)
            implements AutoCloseable {

        public SenderDerivation {
            requireLength(kek, KEK_LENGTH, "kek");
            requireLength(
                    encapsulationCiphertext,
                    ENCAPSULATION_CIPHERTEXT_LENGTH,
                    "encapsulationCiphertext"
            );
            kek = Arrays.copyOf(kek, kek.length);
            encapsulationCiphertext = Arrays.copyOf(
                    encapsulationCiphertext,
                    encapsulationCiphertext.length
            );
        }

        @Override
        public byte[] kek() {
            return Arrays.copyOf(kek, kek.length);
        }

        @Override
        public byte[] encapsulationCiphertext() {
            return Arrays.copyOf(encapsulationCiphertext, encapsulationCiphertext.length);
        }

        @Override
        public void close() {
            clear(kek);
        }
    }
}
