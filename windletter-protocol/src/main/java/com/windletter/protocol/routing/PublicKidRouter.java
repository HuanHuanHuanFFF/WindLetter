package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Routes public-mode recipients by their RFC 7638 X25519 key identifier. */
public final class PublicKidRouter {

    public Match route(
            List<RecipientEntry> recipients,
            List<X25519PrivateKeyHandle> privateKeys
    ) {
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        if (privateKeys == null) {
            throw new IllegalArgumentException("privateKeys must not be null");
        }

        Map<String, X25519PrivateKeyHandle> localByKid = new HashMap<>();
        for (X25519PrivateKeyHandle privateKey : privateKeys) {
            if (privateKey == null) {
                throw invalid("local X25519 private-key handles must not contain null");
            }
            byte[] publicKey = privateKey.publicKey();
            try {
                if (publicKey == null || publicKey.length != 32) {
                    throw invalid("local X25519 handle returned a non-32-byte public key");
                }
                String kid = X25519KeyId.derive(publicKey);
                if (localByKid.putIfAbsent(kid, privateKey) != null) {
                    throw invalid("duplicate local X25519 kid");
                }
            } finally {
                if (publicKey != null) {
                    Arrays.fill(publicKey, (byte) 0);
                }
            }
        }

        Match selected = null;
        Set<String> matchedKids = new HashSet<>();
        for (RecipientEntry entry : recipients) {
            if (!(entry instanceof PublicRecipient recipient)) {
                continue;
            }
            String recipientKid = recipient.kid().x25519();
            X25519PrivateKeyHandle local = localByKid.get(recipientKid);
            if (local == null) {
                continue;
            }
            if (!matchedKids.add(recipientKid)) {
                throw invalid("matching recipient X25519 kid is duplicated");
            }
            if (selected == null) {
                selected = new Match(recipient, local);
            }
        }

        if (selected == null) {
            throw new ProtocolException(ErrorCode.NOT_FOR_ME, "no recipient matches a local X25519 key");
        }
        return selected;
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    public record Match(PublicRecipient recipient, X25519PrivateKeyHandle privateKey) {
        public Match {
            if (recipient == null || privateKey == null) {
                throw new IllegalArgumentException("recipient and privateKey must not be null");
            }
        }
    }
}
