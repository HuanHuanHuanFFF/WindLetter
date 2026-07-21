package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Builds padded and shuffled Hybrid recipient entries for obfuscation mode. */
public final class ObfuscationHybridRecipientBuilder {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;
    private static final int CEK_LENGTH = 32;
    private static final int RID_LENGTH = 16;
    private static final int ENCAPSULATION_CIPHERTEXT_LENGTH = 1088;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final int MAX_RECIPIENTS = 32;
    private static final int MAX_DECOY_RID_ATTEMPTS = 128;

    private final X25519Crypto x25519;
    private final ObfuscationHybridKeyDeriver keyDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final SecureRandom secureRandom;

    public ObfuscationHybridRecipientBuilder(
            X25519Crypto x25519,
            MLKem768Crypto mlkem768,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap
    ) {
        this(x25519, mlkem768, hkdf, keyWrap, new SecureRandom());
    }

    ObfuscationHybridRecipientBuilder(
            X25519Crypto x25519,
            MLKem768Crypto mlkem768,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap,
            SecureRandom secureRandom
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
        if (keyWrap == null) {
            throw new IllegalArgumentException("keyWrap must not be null");
        }
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.x25519 = x25519;
        this.keyDeriver = new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);
        this.keyWrap = keyWrap;
        this.secureRandom = secureRandom;
    }

    public PreparedRecipients build(
            List<ObfuscationHybridRecipientKeys> realRecipients,
            byte[] cek
    ) {
        InputSnapshots inputs = validateAndSnapshotInputs(realRecipients, cek);
        try {
            X25519PrivateKeyHandle ephemeral = x25519.generatePrivateKey();
            if (ephemeral == null) {
                throw new IllegalStateException("X25519 provider returned a null ephemeral handle");
            }
            try (ephemeral) {
                return buildWithEphemeral(ephemeral, inputs);
            }
        } finally {
            clear(inputs.cek());
            clearSpecs(inputs.recipients());
        }
    }

    private PreparedRecipients buildWithEphemeral(
            X25519PrivateKeyHandle ephemeral,
            InputSnapshots inputs
    ) {
        byte[] exportedPublicKey = null;
        byte[] epkX = null;
        try {
            exportedPublicKey = ephemeral.publicKey();
            requireProviderLength(
                    exportedPublicKey,
                    X25519_PUBLIC_KEY_LENGTH,
                    "X25519 provider returned a non-32-byte ephemeral public key"
            );
            epkX = exportedPublicKey.clone();
            Epk epk = new Epk("OKP", "X25519", epkX);

            int targetSize = targetBucket(inputs.recipients().size());
            List<ObfuscationRecipient> recipients = new ArrayList<>(targetSize);
            for (RecipientSpec recipient : inputs.recipients()) {
                addRealRecipient(recipients, ephemeral, recipient, inputs.cek());
            }
            addDecoys(recipients, targetSize);
            shuffle(recipients);
            return new PreparedRecipients(epk, new ArrayList<>(recipients));
        } finally {
            clear(exportedPublicKey);
            clear(epkX);
        }
    }

    private void addRealRecipient(
            List<ObfuscationRecipient> recipients,
            X25519PrivateKeyHandle ephemeral,
            RecipientSpec recipient,
            byte[] cekSnapshot
    ) {
        byte[] rid = null;
        byte[] kek = null;
        byte[] ek = null;
        byte[] wrapped = null;
        try (ObfuscationHybridKeyDeriver.SenderMaterial material =
                     keyDeriver.deriveForSender(
                             ephemeral,
                             recipient.x25519PublicKey(),
                             recipient.mlkem768PublicKey()
                     )) {
            rid = material.rid();
            kek = material.kek();
            ek = material.ek();
            wrapped = wrapCek(kek, cekSnapshot);
            requireProviderLength(
                    wrapped,
                    WRAPPED_CEK_LENGTH,
                    "A256KW provider returned a non-40-byte wrapped CEK"
            );
            if (containsRid(recipients, rid)) {
                throw new IllegalStateException("real recipient rid collision");
            }
            recipients.add(new ObfuscationRecipient(rid, wrapped, ek));
        } finally {
            clear(rid);
            clear(kek);
            clear(ek);
            clear(wrapped);
        }
    }

    private byte[] wrapCek(byte[] kek, byte[] cekSnapshot) {
        byte[] providerCek = cekSnapshot.clone();
        try {
            try {
                return keyWrap.wrap(kek, providerCek);
            } catch (RuntimeException cause) {
                throw new IllegalStateException("A256KW provider failed to wrap CEK", cause);
            }
        } finally {
            clear(providerCek);
        }
    }

    private void addDecoys(List<ObfuscationRecipient> recipients, int targetSize) {
        while (recipients.size() < targetSize) {
            byte[] rid = new byte[RID_LENGTH];
            byte[] ek = null;
            byte[] encryptedKey = null;
            try {
                boolean unique = false;
                for (int attempt = 0; attempt < MAX_DECOY_RID_ATTEMPTS; attempt++) {
                    nextBytes(rid);
                    if (!containsRid(recipients, rid)) {
                        unique = true;
                        break;
                    }
                }
                if (!unique) {
                    throw new IllegalStateException(
                            "decoy rid remained non-unique after 128 attempts"
                    );
                }

                ek = new byte[ENCAPSULATION_CIPHERTEXT_LENGTH];
                nextBytes(ek);
                encryptedKey = new byte[WRAPPED_CEK_LENGTH];
                nextBytes(encryptedKey);
                recipients.add(new ObfuscationRecipient(rid, encryptedKey, ek));
            } finally {
                clear(rid);
                clear(ek);
                clear(encryptedKey);
            }
        }
    }

    private void nextBytes(byte[] destination) {
        try {
            secureRandom.nextBytes(destination);
        } catch (RuntimeException cause) {
            throw new IllegalStateException("SecureRandom nextBytes failed", cause);
        }
    }

    private void shuffle(List<ObfuscationRecipient> recipients) {
        for (int i = recipients.size() - 1; i > 0; i--) {
            final int swapIndex;
            try {
                swapIndex = secureRandom.nextInt(i + 1);
            } catch (RuntimeException cause) {
                throw new IllegalStateException("SecureRandom nextInt failed", cause);
            }
            Collections.swap(recipients, i, swapIndex);
        }
    }

    private static InputSnapshots validateAndSnapshotInputs(
            List<ObfuscationHybridRecipientKeys> realRecipients,
            byte[] cek
    ) {
        if (realRecipients == null) {
            throw new IllegalArgumentException("realRecipients must not be null");
        }
        if (realRecipients.isEmpty() || realRecipients.size() > MAX_RECIPIENTS) {
            throw new IllegalArgumentException("realRecipients must contain 1..32 entries");
        }
        if (cek == null || cek.length != CEK_LENGTH) {
            throw new IllegalArgumentException("cek must contain exactly 32 bytes");
        }

        List<RecipientSpec> snapshots = new ArrayList<>(realRecipients.size());
        try {
            for (ObfuscationHybridRecipientKeys recipient : realRecipients) {
                if (recipient == null) {
                    throw new IllegalArgumentException("realRecipients must not contain null");
                }
                byte[] x25519PublicKey = recipient.x25519PublicKey();
                byte[] mlkem768PublicKey = recipient.mlkem768PublicKey();
                boolean added = false;
                try {
                    requireInputLength(
                            x25519PublicKey,
                            X25519_PUBLIC_KEY_LENGTH,
                            "recipient X25519 public key"
                    );
                    requireInputLength(
                            mlkem768PublicKey,
                            MLKEM768_PUBLIC_KEY_LENGTH,
                            "recipient ML-KEM-768 public key"
                    );
                    if (containsPair(snapshots, x25519PublicKey, mlkem768PublicKey)) {
                        throw new IllegalArgumentException("duplicate hybrid recipient key pair");
                    }
                    snapshots.add(new RecipientSpec(x25519PublicKey, mlkem768PublicKey));
                    added = true;
                } finally {
                    if (!added) {
                        clear(x25519PublicKey);
                        clear(mlkem768PublicKey);
                    }
                }
            }
            return new InputSnapshots(List.copyOf(snapshots), cek.clone());
        } catch (RuntimeException failure) {
            clearSpecs(snapshots);
            throw failure;
        }
    }

    private static boolean containsPair(
            List<RecipientSpec> recipients,
            byte[] x25519PublicKey,
            byte[] mlkem768PublicKey
    ) {
        for (RecipientSpec recipient : recipients) {
            if (MessageDigest.isEqual(recipient.x25519PublicKey(), x25519PublicKey)
                    && MessageDigest.isEqual(recipient.mlkem768PublicKey(), mlkem768PublicKey)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsRid(
            List<ObfuscationRecipient> recipients,
            byte[] expectedRid
    ) {
        for (ObfuscationRecipient recipient : recipients) {
            byte[] candidate = recipient.rid();
            try {
                if (MessageDigest.isEqual(expectedRid, candidate)) {
                    return true;
                }
            } finally {
                clear(candidate);
            }
        }
        return false;
    }

    private static int targetBucket(int realRecipientCount) {
        if (realRecipientCount <= 8) {
            return 8;
        }
        if (realRecipientCount <= 16) {
            return 16;
        }
        return 32;
    }

    private static boolean isBucketSize(int size) {
        return size == 8 || size == 16 || size == 32;
    }

    private static void requireInputLength(byte[] value, int expectedLength, String name) {
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

    private static void clearSpecs(List<RecipientSpec> recipients) {
        for (RecipientSpec recipient : recipients) {
            clear(recipient.x25519PublicKey());
            clear(recipient.mlkem768PublicKey());
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record RecipientSpec(byte[] x25519PublicKey, byte[] mlkem768PublicKey) {
    }

    private record InputSnapshots(List<RecipientSpec> recipients, byte[] cek) {
    }

    /** Immutable final wire EPK and shuffled Hybrid recipient bucket. */
    public record PreparedRecipients(Epk epk, List<RecipientEntry> recipients) {

        public PreparedRecipients {
            if (epk == null) {
                throw new IllegalArgumentException("epk must not be null");
            }
            if (!"OKP".equals(epk.kty()) || !"X25519".equals(epk.crv())) {
                throw new IllegalArgumentException("epk must use OKP/X25519");
            }

            byte[] epkX = epk.x();
            try {
                if (epkX.length != X25519_PUBLIC_KEY_LENGTH) {
                    throw new IllegalArgumentException("epk.x must contain exactly 32 bytes");
                }
                epk = new Epk("OKP", "X25519", epkX);
            } finally {
                clear(epkX);
            }

            if (recipients == null) {
                throw new IllegalArgumentException("recipients must not be null");
            }
            if (!isBucketSize(recipients.size())) {
                throw new IllegalArgumentException(
                        "recipients must contain exactly 8, 16, or 32 entries"
                );
            }

            List<ObfuscationRecipient> snapshots = new ArrayList<>(recipients.size());
            for (RecipientEntry entry : recipients) {
                if (!(entry instanceof ObfuscationRecipient recipient)) {
                    throw new IllegalArgumentException(
                            "recipients must contain only obfuscation entries"
                    );
                }
                byte[] rid = recipient.rid();
                byte[] encryptedKey = recipient.encryptedKey();
                byte[] ek = recipient.ek();
                try {
                    if (rid.length != RID_LENGTH) {
                        throw new IllegalArgumentException(
                                "recipient rid must contain exactly 16 bytes"
                        );
                    }
                    if (encryptedKey.length != WRAPPED_CEK_LENGTH) {
                        throw new IllegalArgumentException(
                                "recipient encryptedKey must contain exactly 40 bytes"
                        );
                    }
                    if (ek == null || ek.length != ENCAPSULATION_CIPHERTEXT_LENGTH) {
                        throw new IllegalArgumentException(
                                "obfuscation Hybrid recipient ek must contain exactly 1088 bytes"
                        );
                    }
                    if (containsRid(snapshots, rid)) {
                        throw new IllegalArgumentException("recipient rids must be unique");
                    }
                    snapshots.add(new ObfuscationRecipient(rid, encryptedKey, ek));
                } finally {
                    clear(rid);
                    clear(encryptedKey);
                    clear(ek);
                }
            }
            recipients = List.copyOf(new ArrayList<>(snapshots));
        }
    }
}
