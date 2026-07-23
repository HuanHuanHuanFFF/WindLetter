package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientKid;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Builds public-mode X25519/ML-KEM-768 recipient entries for a shared CEK. */
public final class PublicHybridRecipientBuilder {

    private static final int CEK_LENGTH = 32;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final int ENCAPSULATION_CIPHERTEXT_LENGTH = 1088;
    private static final int MAX_RECIPIENTS = 32;

    private final PublicHybridKekDeriver kekDeriver;
    private final A256KeyWrapCrypto keyWrap;

    public PublicHybridRecipientBuilder(
            PublicHybridKekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap
    ) {
        if (kekDeriver == null) {
            throw new IllegalArgumentException("kekDeriver must not be null");
        }
        if (keyWrap == null) {
            throw new IllegalArgumentException("keyWrap must not be null");
        }
        this.kekDeriver = kekDeriver;
        this.keyWrap = keyWrap;
    }

    /** Builds immutable recipient entries in caller-provided order. */
    public List<PublicRecipient> build(
            X25519PrivateKeyHandle senderKey,
            List<PublicHybridRecipientKeys> recipients,
            byte[] cek
    ) {
        validateTopLevel(senderKey, recipients, cek);
        List<RecipientSpec> specs = validateAndSnapshotRecipients(recipients);
        byte[] cekSnapshot = cek.clone();
        try {
            List<PublicRecipient> result = new ArrayList<>(specs.size());
            for (RecipientSpec spec : specs) {
                byte[] kek = null;
                byte[] ek = null;
                byte[] wrapped = null;
                try (PublicHybridKekDeriver.SenderDerivation derived =
                             kekDeriver.deriveForSender(
                                     senderKey,
                                     spec.x25519PublicKey(),
                                     spec.mlkem768PublicKey()
                             )) {
                    kek = derived.kek();
                    ek = derived.encapsulationCiphertext();
                    if (ek.length != ENCAPSULATION_CIPHERTEXT_LENGTH) {
                        throw new IllegalStateException(
                                "hybrid deriver returned a non-1088-byte encapsulation ciphertext"
                        );
                    }

                    wrapped = keyWrap.wrap(kek, cekSnapshot);
                    if (wrapped == null || wrapped.length != WRAPPED_CEK_LENGTH) {
                        throw new IllegalStateException(
                                "A256KW provider returned a non-40-byte wrapped CEK"
                        );
                    }

                    result.add(new PublicRecipient(
                            new RecipientKid(spec.x25519Kid(), spec.mlkem768Kid()),
                            wrapped,
                            ek
                    ));
                } finally {
                    clear(kek);
                    clear(ek);
                    clear(wrapped);
                }
            }
            return List.copyOf(result);
        } finally {
            clear(cekSnapshot);
            clearSpecs(specs);
        }
    }

    private static void validateTopLevel(
            X25519PrivateKeyHandle senderKey,
            List<PublicHybridRecipientKeys> recipients,
            byte[] cek
    ) {
        if (senderKey == null) {
            throw new IllegalArgumentException("senderKey must not be null");
        }
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        if (recipients.isEmpty() || recipients.size() > MAX_RECIPIENTS) {
            throw new IllegalArgumentException("recipients must contain 1..32 entries");
        }
        if (cek == null || cek.length != CEK_LENGTH) {
            throw new IllegalArgumentException("cek must contain exactly 32 bytes");
        }
    }

    private static List<RecipientSpec> validateAndSnapshotRecipients(
            List<PublicHybridRecipientKeys> recipients
    ) {
        List<RawRecipient> snapshots = new ArrayList<>(recipients.size());
        for (PublicHybridRecipientKeys keys : recipients) {
            if (keys == null) {
                clearRawRecipients(snapshots);
                throw new IllegalArgumentException("recipients must not contain null");
            }
            snapshots.add(new RawRecipient(keys.x25519PublicKey(), keys.mlkem768PublicKey()));
        }

        List<RecipientSpec> specs = new ArrayList<>(snapshots.size());
        Set<RecipientPairId> seenPairs = new HashSet<>(snapshots.size());
        try {
            for (RawRecipient snapshot : snapshots) {
                String x25519Kid = X25519KeyId.derive(snapshot.x25519PublicKey());
                String mlkem768Kid = MLKem768KeyId.derive(snapshot.mlkem768PublicKey());
                if (!seenPairs.add(new RecipientPairId(x25519Kid, mlkem768Kid))) {
                    clearSpecs(specs);
                    throw new IllegalArgumentException("duplicate hybrid recipient key pair");
                }
                specs.add(new RecipientSpec(
                        snapshot.x25519PublicKey().clone(),
                        snapshot.mlkem768PublicKey().clone(),
                        x25519Kid,
                        mlkem768Kid
                ));
            }
            return List.copyOf(specs);
        } finally {
            clearRawRecipients(snapshots);
        }
    }

    private static void clearRawRecipients(List<RawRecipient> recipients) {
        for (RawRecipient recipient : recipients) {
            clear(recipient.x25519PublicKey());
            clear(recipient.mlkem768PublicKey());
        }
    }

    private static void clearSpecs(List<RecipientSpec> specs) {
        for (RecipientSpec spec : specs) {
            clear(spec.x25519PublicKey());
            clear(spec.mlkem768PublicKey());
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record RawRecipient(byte[] x25519PublicKey, byte[] mlkem768PublicKey) {
    }

    private record RecipientSpec(
            byte[] x25519PublicKey,
            byte[] mlkem768PublicKey,
            String x25519Kid,
            String mlkem768Kid
    ) {
    }

    private record RecipientPairId(String x25519Kid, String mlkem768Kid) {
    }
}
