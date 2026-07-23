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

/** Derives obfuscation-mode X25519/ML-KEM-768 recipient identifiers and KEKs. */
public final class ObfuscationHybridKeyDeriver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;
    private static final int SHARED_SECRET_LENGTH = 32;
    private static final int ENCAPSULATION_CIPHERTEXT_LENGTH = 1088;
    private static final int RID_LENGTH = 16;
    private static final int KEK_LENGTH = 32;
    private static final byte[] HKDF_SALT = "wind".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_RID_INFO = "rid/hybrid".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_KEK_INFO =
            "WindLetter v1 KEK | X25519ML-KEM-768".getBytes(StandardCharsets.UTF_8);

    private final X25519Crypto x25519;
    private final MLKem768Crypto mlkem768;
    private final HkdfCrypto hkdf;

    public ObfuscationHybridKeyDeriver(
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
     * Performs one recipient-specific encapsulation and derives its rid and KEK.
     * The ephemeral private-key handle is borrowed and remains caller-owned.
     */
    public SenderMaterial deriveForSender(
            X25519PrivateKeyHandle ephemeral,
            byte[] recipientX25519PublicKey,
            byte[] recipientMlkem768PublicKey
    ) {
        requireHandle(ephemeral, "ephemeral");
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
        byte[] ek = null;
        DerivedOutputs outputs = null;
        try {
            ssEcc = x25519.deriveSharedSecret(
                    ephemeral,
                    recipientX25519PublicKey.clone()
            );
            requireProviderLength(
                    ssEcc,
                    SHARED_SECRET_LENGTH,
                    "X25519 provider returned a non-32-byte shared secret"
            );
            rejectAllZeroX25519(ssEcc);

            MLKem768Encapsulation encapsulation =
                    mlkem768.encapsulate(recipientMlkem768PublicKey.clone());
            if (encapsulation == null) {
                throw new IllegalStateException("ML-KEM provider returned a null encapsulation");
            }
            try (encapsulation) {
                ek = encapsulation.ciphertext();
                requireProviderLength(
                        ek,
                        ENCAPSULATION_CIPHERTEXT_LENGTH,
                        "ML-KEM provider returned a non-1088-byte encapsulation ciphertext"
                );
                ssPq = encapsulation.sharedSecret();
                requireProviderLength(
                        ssPq,
                        SHARED_SECRET_LENGTH,
                        "ML-KEM provider returned a non-32-byte shared secret"
                );
                outputs = deriveOutputs(hkdf, ssEcc, ssPq);
                return new SenderMaterial(outputs.rid(), outputs.kek(), ek);
            }
        } finally {
            clear(ssEcc);
            clear(ssPq);
            clear(ek);
            if (outputs != null) {
                outputs.clear();
            }
        }
    }

    /**
     * Opens a per-local-pair receiver context. Candidate X25519 failures are
     * latched so the caller can continue a fixed full scan before rejecting.
     */
    public ReceiverContext openForReceiver(
            X25519PrivateKeyHandle recipientX25519PrivateKey,
            MLKem768PrivateKeyHandle recipientMlkem768PrivateKey,
            byte[] epkX
    ) {
        requireHandle(recipientX25519PrivateKey, "recipientX25519PrivateKey");
        requireHandle(recipientMlkem768PrivateKey, "recipientMlkem768PrivateKey");
        requireLength(epkX, X25519_PUBLIC_KEY_LENGTH, "epkX");

        byte[] ssEcc = null;
        boolean candidateCryptoFailed = false;
        try {
            try {
                ssEcc = x25519.deriveSharedSecret(
                        recipientX25519PrivateKey,
                        epkX.clone()
                );
            } catch (CryptoOperationException candidateFailure) {
                candidateCryptoFailed = true;
                ssEcc = new byte[SHARED_SECRET_LENGTH];
            }
            requireProviderLength(
                    ssEcc,
                    SHARED_SECRET_LENGTH,
                    "X25519 provider returned a non-32-byte shared secret"
            );
            if (allZero(ssEcc)) {
                candidateCryptoFailed = true;
            }
            return new ReceiverContext(
                    mlkem768,
                    hkdf,
                    recipientMlkem768PrivateKey,
                    ssEcc,
                    candidateCryptoFailed
            );
        } finally {
            clear(ssEcc);
        }
    }

    private static DerivedOutputs deriveOutputs(
            HkdfCrypto hkdf,
            byte[] ssEcc,
            byte[] ssPq
    ) {
        requireLength(ssEcc, SHARED_SECRET_LENGTH, "ssEcc");
        requireLength(ssPq, SHARED_SECRET_LENGTH, "ssPq");

        byte[] z = new byte[SHARED_SECRET_LENGTH * 2];
        byte[] rid = null;
        byte[] kek = null;
        boolean completed = false;
        try {
            System.arraycopy(ssEcc, 0, z, 0, SHARED_SECRET_LENGTH);
            System.arraycopy(ssPq, 0, z, SHARED_SECRET_LENGTH, SHARED_SECRET_LENGTH);

            rid = deriveHkdf(hkdf, z, HKDF_RID_INFO, RID_LENGTH);
            requireProviderLength(
                    rid,
                    RID_LENGTH,
                    "HKDF provider returned a non-16-byte rid"
            );
            kek = deriveHkdf(hkdf, z, HKDF_KEK_INFO, KEK_LENGTH);
            requireProviderLength(
                    kek,
                    KEK_LENGTH,
                    "HKDF provider returned a non-32-byte KEK"
            );
            DerivedOutputs outputs = new DerivedOutputs(rid, kek);
            completed = true;
            return outputs;
        } finally {
            if (!completed) {
                clear(rid);
                clear(kek);
            }
            clear(z);
        }
    }

    private static byte[] deriveHkdf(
            HkdfCrypto hkdf,
            byte[] z,
            byte[] info,
            int length
    ) {
        byte[] hkdfInput = z.clone();
        try {
            return hkdf.derive(HKDF_SALT.clone(), hkdfInput, info.clone(), length);
        } catch (CryptoOperationException cause) {
            throw new IllegalStateException("HKDF provider failed", cause);
        } finally {
            clear(hkdfInput);
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

    private static void requireProviderLength(
            byte[] value,
            int expectedLength,
            String message
    ) {
        if (value == null || value.length != expectedLength) {
            clear(value);
            throw new IllegalStateException(message);
        }
    }

    private static void rejectAllZeroX25519(byte[] sharedSecret) {
        if (allZero(sharedSecret)) {
            throw new CryptoOperationException(
                    "failed to derive X25519 shared secret: low-order public key"
            );
        }
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record DerivedOutputs(byte[] rid, byte[] kek) {
        private void clear() {
            ObfuscationHybridKeyDeriver.clear(rid);
            ObfuscationHybridKeyDeriver.clear(kek);
        }
    }

    /** Sender-owned derived material. */
    public static final class SenderMaterial implements AutoCloseable {

        private final byte[] rid;
        private final byte[] kek;
        private final byte[] ek;
        private boolean destroyed;

        private SenderMaterial(byte[] rid, byte[] kek, byte[] ek) {
            requireProviderLength(rid, RID_LENGTH, "rid must contain exactly 16 bytes");
            requireProviderLength(kek, KEK_LENGTH, "kek must contain exactly 32 bytes");
            requireProviderLength(
                    ek,
                    ENCAPSULATION_CIPHERTEXT_LENGTH,
                    "ek must contain exactly 1088 bytes"
            );
            this.rid = rid.clone();
            this.kek = kek.clone();
            this.ek = ek.clone();
        }

        public byte[] rid() {
            ensureNotDestroyed();
            return rid.clone();
        }

        public byte[] kek() {
            ensureNotDestroyed();
            return kek.clone();
        }

        public byte[] ek() {
            ensureNotDestroyed();
            return ek.clone();
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
                throw new IllegalStateException("sender material is closed");
            }
        }
    }

    /** Per-local-pair receiver context; private-key handles remain borrowed. */
    public static final class ReceiverContext implements AutoCloseable {

        private final MLKem768Crypto mlkem768;
        private final HkdfCrypto hkdf;
        private final MLKem768PrivateKeyHandle recipientMlkem768PrivateKey;
        private final byte[] ssEcc;
        private final boolean candidateCryptoFailed;
        private boolean destroyed;

        private ReceiverContext(
                MLKem768Crypto mlkem768,
                HkdfCrypto hkdf,
                MLKem768PrivateKeyHandle recipientMlkem768PrivateKey,
                byte[] ssEcc,
                boolean candidateCryptoFailed
        ) {
            this.mlkem768 = mlkem768;
            this.hkdf = hkdf;
            this.recipientMlkem768PrivateKey = recipientMlkem768PrivateKey;
            this.ssEcc = ssEcc.clone();
            this.candidateCryptoFailed = candidateCryptoFailed;
        }

        /**
         * Reports only the X25519 failure latched for this local key pair.
         * Callers performing a full scan must also OR every per-entry
         * {@link DerivedMaterial#candidateCryptoFailed()} result.
         */
        public boolean candidateCryptoFailed() {
            ensureNotDestroyed();
            return candidateCryptoFailed;
        }

        public DerivedMaterial deriveEntry(byte[] ek) {
            ensureNotDestroyed();
            requireLength(ek, ENCAPSULATION_CIPHERTEXT_LENGTH, "ek");

            byte[] ssPq = null;
            DerivedOutputs outputs = null;
            boolean entryCryptoFailed = candidateCryptoFailed;
            try {
                try {
                    ssPq = mlkem768.decapsulate(
                            recipientMlkem768PrivateKey,
                            ek.clone()
                    );
                } catch (CryptoOperationException candidateFailure) {
                    entryCryptoFailed = true;
                    ssPq = new byte[SHARED_SECRET_LENGTH];
                }
                requireProviderLength(
                        ssPq,
                        SHARED_SECRET_LENGTH,
                        "ML-KEM provider returned a non-32-byte shared secret"
                );
                outputs = deriveOutputs(hkdf, ssEcc, ssPq);
                return new DerivedMaterial(
                        outputs.rid(),
                        outputs.kek(),
                        entryCryptoFailed
                );
            } finally {
                clear(ssPq);
                if (outputs != null) {
                    outputs.clear();
                }
            }
        }

        @Override
        public void close() {
            if (!destroyed) {
                clear(ssEcc);
                destroyed = true;
            }
        }

        private void ensureNotDestroyed() {
            if (destroyed) {
                throw new IllegalStateException("receiver context is closed");
            }
        }
    }

    /** Receiver-owned per-entry material. */
    public static final class DerivedMaterial implements AutoCloseable {

        private final byte[] rid;
        private final byte[] kek;
        private final boolean candidateCryptoFailed;
        private boolean destroyed;

        private DerivedMaterial(byte[] rid, byte[] kek, boolean candidateCryptoFailed) {
            requireProviderLength(rid, RID_LENGTH, "rid must contain exactly 16 bytes");
            requireProviderLength(kek, KEK_LENGTH, "kek must contain exactly 32 bytes");
            this.rid = rid.clone();
            this.kek = kek.clone();
            this.candidateCryptoFailed = candidateCryptoFailed;
        }

        public byte[] rid() {
            ensureNotDestroyed();
            return rid.clone();
        }

        public byte[] kek() {
            ensureNotDestroyed();
            return kek.clone();
        }

        /** Reports the cumulative X25519 or ML-KEM failure for this candidate. */
        public boolean candidateCryptoFailed() {
            ensureNotDestroyed();
            return candidateCryptoFailed;
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
