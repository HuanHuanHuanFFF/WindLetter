package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Builds padded and shuffled X25519 recipient entries for obfuscation mode. */
public final class ObfuscationX25519RecipientBuilder {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int CEK_LENGTH = 32;
    private static final int RID_LENGTH = 16;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final int MAX_RECIPIENTS = 32;
    private static final int MAX_DECOY_RID_ATTEMPTS = 128;

    private final X25519Crypto x25519;
    private final ObfuscationX25519KeyDeriver keyDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final SecureRandom secureRandom;

    public ObfuscationX25519RecipientBuilder(
            X25519Crypto x25519,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap
    ) {
        this(x25519, hkdf, keyWrap, new SecureRandom());
    }

    ObfuscationX25519RecipientBuilder(
            X25519Crypto x25519,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap,
            SecureRandom secureRandom
    ) {
        if (x25519 == null) {
            throw new IllegalArgumentException("x25519 must not be null");
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
        this.keyDeriver = new ObfuscationX25519KeyDeriver(x25519, hkdf);
        this.keyWrap = keyWrap;
        this.secureRandom = secureRandom;
    }

    public PreparedRecipients build(List<byte[]> realRecipientPublicKeys, byte[] cek) {
        InputSnapshots inputs = validateAndSnapshotInputs(realRecipientPublicKeys, cek);
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
            clearAll(inputs.recipientPublicKeys());
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
            if (exportedPublicKey == null || exportedPublicKey.length != X25519_PUBLIC_KEY_LENGTH) {
                throw new IllegalStateException(
                        "X25519 provider returned a non-32-byte ephemeral public key"
                );
            }
            epkX = exportedPublicKey.clone();
            Epk epk = new Epk("OKP", "X25519", epkX);

            List<ObfuscationRecipient> recipients = new ArrayList<>(
                    targetBucket(inputs.recipientPublicKeys().size())
            );
            for (byte[] recipientPublicKey : inputs.recipientPublicKeys()) {
                addRealRecipient(recipients, ephemeral, recipientPublicKey, inputs.cek());
            }
            addDecoys(recipients, targetBucket(recipients.size()));
            shuffle(recipients);

            List<RecipientEntry> wireEntries = new ArrayList<>(recipients);
            return new PreparedRecipients(epk, wireEntries);
        } finally {
            clear(exportedPublicKey);
            clear(epkX);
        }
    }

    private void addRealRecipient(
            List<ObfuscationRecipient> recipients,
            X25519PrivateKeyHandle ephemeral,
            byte[] recipientPublicKey,
            byte[] cekSnapshot
    ) {
        byte[] rid = null;
        byte[] kek = null;
        byte[] wrapped = null;
        try (ObfuscationX25519KeyDeriver.DerivedMaterial material =
                     keyDeriver.derive(ephemeral, recipientPublicKey)) {
            rid = material.rid();
            kek = material.kek();
            wrapped = wrapCek(kek, cekSnapshot);
            if (wrapped == null || wrapped.length != WRAPPED_CEK_LENGTH) {
                throw new IllegalStateException(
                        "A256KW provider returned a non-40-byte wrapped CEK"
                );
            }
            if (containsRid(recipients, rid)) {
                throw new IllegalStateException("real recipient rid collision");
            }
            recipients.add(new ObfuscationRecipient(rid, wrapped, null));
        } finally {
            clear(rid);
            clear(kek);
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

                encryptedKey = new byte[WRAPPED_CEK_LENGTH];
                nextBytes(encryptedKey);
                recipients.add(new ObfuscationRecipient(rid, encryptedKey, null));
            } finally {
                clear(rid);
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
            final int j;
            try {
                j = secureRandom.nextInt(i + 1);
            } catch (RuntimeException cause) {
                throw new IllegalStateException("SecureRandom nextInt failed", cause);
            }
            Collections.swap(recipients, i, j);
        }
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

    private static InputSnapshots validateAndSnapshotInputs(
            List<byte[]> realRecipientPublicKeys,
            byte[] cek
    ) {
        if (realRecipientPublicKeys == null) {
            throw new IllegalArgumentException("realRecipientPublicKeys must not be null");
        }
        if (realRecipientPublicKeys.isEmpty()
                || realRecipientPublicKeys.size() > MAX_RECIPIENTS) {
            throw new IllegalArgumentException(
                    "realRecipientPublicKeys must contain 1..32 entries"
            );
        }
        if (cek == null || cek.length != CEK_LENGTH) {
            throw new IllegalArgumentException("cek must contain exactly 32 bytes");
        }

        List<byte[]> snapshots = new ArrayList<>(realRecipientPublicKeys.size());
        try {
            for (byte[] publicKey : realRecipientPublicKeys) {
                if (publicKey == null || publicKey.length != X25519_PUBLIC_KEY_LENGTH) {
                    throw new IllegalArgumentException(
                            "each real recipient public key must contain exactly 32 bytes"
                    );
                }
                byte[] snapshot = publicKey.clone();
                if (containsBytes(snapshots, snapshot)) {
                    clear(snapshot);
                    throw new IllegalArgumentException("duplicate real recipient public key");
                }
                snapshots.add(snapshot);
            }
            return new InputSnapshots(List.copyOf(snapshots), cek.clone());
        } catch (RuntimeException failure) {
            clearAll(snapshots);
            throw failure;
        }
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

    private static boolean containsBytes(List<byte[]> values, byte[] candidate) {
        for (byte[] value : values) {
            if (MessageDigest.isEqual(value, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isBucketSize(int size) {
        return size == 8 || size == 16 || size == 32;
    }

    private static void clearAll(List<byte[]> values) {
        for (byte[] value : values) {
            clear(value);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record InputSnapshots(List<byte[]> recipientPublicKeys, byte[] cek) {
    }

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
                throw new IllegalArgumentException("recipients must contain exactly 8, 16, or 32 entries");
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
                byte[] entryEk = recipient.ek();
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
                    if (entryEk != null) {
                        throw new IllegalArgumentException(
                                "obfuscation X25519 recipient ek must be null"
                        );
                    }
                    if (containsRid(snapshots, rid)) {
                        throw new IllegalArgumentException("recipient rids must be unique");
                    }
                    snapshots.add(new ObfuscationRecipient(rid, encryptedKey, null));
                } finally {
                    clear(rid);
                    clear(encryptedKey);
                    clear(entryEk);
                }
            }
            List<RecipientEntry> recipientSnapshots = new ArrayList<>(snapshots);
            recipients = List.copyOf(recipientSnapshots);
        }
    }
}
