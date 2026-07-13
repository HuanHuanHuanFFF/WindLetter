package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientKid;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds public-mode X25519 recipient entries for a shared content-encryption key.
 */
public final class PublicX25519RecipientBuilder {

    private static final int KEY_LENGTH = 32;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final int MAX_RECIPIENTS = 32;

    private final PublicX25519KekDeriver kekDeriver;
    private final A256KeyWrapCrypto keyWrap;

    public PublicX25519RecipientBuilder(
            PublicX25519KekDeriver kekDeriver,
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

    /**
     * Builds recipient entries in caller-provided order. The sender handle and CEK remain caller-owned.
     */
    public List<PublicRecipient> build(
            X25519PrivateKeyHandle senderKey,
            List<byte[]> recipientPublicKeys,
            byte[] cek
    ) {
        validateTopLevel(senderKey, recipientPublicKeys, cek);

        byte[] cekSnapshot = cek.clone();
        try {
            List<RecipientSpec> specs = validateAndSnapshotRecipients(recipientPublicKeys);
            List<PublicRecipient> recipients = new ArrayList<>(specs.size());
            for (RecipientSpec spec : specs) {
                byte[] kek = kekDeriver.derive(senderKey, spec.publicKey());
                try {
                    byte[] wrapped = keyWrap.wrap(kek, cekSnapshot);
                    if (wrapped == null || wrapped.length != WRAPPED_CEK_LENGTH) {
                        if (wrapped != null) {
                            Arrays.fill(wrapped, (byte) 0);
                        }
                        throw new IllegalStateException("A256KW provider returned a non-40-byte wrapped CEK");
                    }
                    recipients.add(new PublicRecipient(
                            new RecipientKid(spec.kid(), null),
                            wrapped,
                            null
                    ));
                } finally {
                    Arrays.fill(kek, (byte) 0);
                }
            }
            return List.copyOf(recipients);
        } finally {
            Arrays.fill(cekSnapshot, (byte) 0);
        }
    }

    private static void validateTopLevel(
            X25519PrivateKeyHandle senderKey,
            List<byte[]> recipientPublicKeys,
            byte[] cek
    ) {
        if (senderKey == null) {
            throw new IllegalArgumentException("senderKey must not be null");
        }
        if (recipientPublicKeys == null) {
            throw new IllegalArgumentException("recipientPublicKeys must not be null");
        }
        if (recipientPublicKeys.isEmpty() || recipientPublicKeys.size() > MAX_RECIPIENTS) {
            throw new IllegalArgumentException("recipientPublicKeys must contain 1..32 entries");
        }
        if (cek == null || cek.length != KEY_LENGTH) {
            throw new IllegalArgumentException("cek must contain exactly 32 bytes");
        }
    }

    private static List<RecipientSpec> validateAndSnapshotRecipients(List<byte[]> recipientPublicKeys) {
        List<RecipientSpec> specs = new ArrayList<>(recipientPublicKeys.size());
        Set<String> seenKids = new HashSet<>(recipientPublicKeys.size());
        for (byte[] publicKey : recipientPublicKeys) {
            if (publicKey == null || publicKey.length != KEY_LENGTH) {
                throw new IllegalArgumentException("each recipient public key must contain exactly 32 bytes");
            }
            byte[] snapshot = publicKey.clone();
            String kid = X25519KeyId.derive(snapshot);
            if (!seenKids.add(kid)) {
                throw new IllegalArgumentException("duplicate recipient X25519 kid");
            }
            specs.add(new RecipientSpec(snapshot, kid));
        }
        return specs;
    }

    private record RecipientSpec(byte[] publicKey, String kid) {
    }
}
