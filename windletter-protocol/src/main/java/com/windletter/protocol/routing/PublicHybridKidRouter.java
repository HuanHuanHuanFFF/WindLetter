package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Routes public-mode hybrid recipients by the complete X25519/ML-KEM-768 kid pair. */
public final class PublicHybridKidRouter {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;

    public Match route(
            List<RecipientEntry> recipients,
            List<PublicHybridRecipientPrivateKeys> privateKeys
    ) {
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        if (privateKeys == null) {
            throw new IllegalArgumentException("privateKeys must not be null");
        }

        Map<KidPair, PublicHybridRecipientPrivateKeys> localByPair =
                buildValidatedLocalMap(privateKeys);
        Match first = null;
        Set<KidPair> matchedWirePairs = new HashSet<>();
        for (RecipientEntry entry : recipients) {
            if (!(entry instanceof PublicRecipient recipient)) {
                continue;
            }
            String x25519Kid = recipient.kid().x25519();
            String mlkem768Kid = recipient.kid().mlkem768();
            if (mlkem768Kid == null) {
                throw invalid("public hybrid recipient must contain an ML-KEM-768 kid");
            }

            KidPair pair = new KidPair(x25519Kid, mlkem768Kid);
            PublicHybridRecipientPrivateKeys local = localByPair.get(pair);
            if (local == null) {
                continue;
            }
            if (!matchedWirePairs.add(pair)) {
                throw invalid("matching hybrid recipient pair is duplicated");
            }
            if (first == null) {
                first = new Match(
                        recipient,
                        local.x25519PrivateKey(),
                        local.mlkem768PrivateKey()
                );
            }
        }

        if (first == null) {
            throw new ProtocolException(
                    ErrorCode.NOT_FOR_ME,
                    "no hybrid recipient pair matches local keys"
            );
        }
        return first;
    }

    private static Map<KidPair, PublicHybridRecipientPrivateKeys> buildValidatedLocalMap(
            List<PublicHybridRecipientPrivateKeys> privateKeys
    ) {
        Map<KidPair, PublicHybridRecipientPrivateKeys> localByPair = new HashMap<>();
        for (PublicHybridRecipientPrivateKeys privateKeyPair : privateKeys) {
            if (privateKeyPair == null) {
                throw invalid("local hybrid private-key pairs must not contain null");
            }

            byte[] x25519PublicKey = null;
            byte[] mlkem768PublicKey = null;
            KidPair kidPair;
            try {
                x25519PublicKey = privateKeyPair.x25519PrivateKey().publicKey();
                requireProviderLength(
                        x25519PublicKey,
                        X25519_PUBLIC_KEY_LENGTH,
                        "local X25519 handle"
                );
                mlkem768PublicKey = privateKeyPair.mlkem768PrivateKey().publicKey();
                requireProviderLength(
                        mlkem768PublicKey,
                        MLKEM768_PUBLIC_KEY_LENGTH,
                        "local ML-KEM-768 handle"
                );
                kidPair = new KidPair(
                        X25519KeyId.derive(x25519PublicKey),
                        MLKem768KeyId.derive(mlkem768PublicKey)
                );
            } catch (RuntimeException e) {
                throw internal("failed to inspect local hybrid key handles", e);
            } finally {
                clear(x25519PublicKey);
                clear(mlkem768PublicKey);
            }

            if (localByPair.putIfAbsent(kidPair, privateKeyPair) != null) {
                throw invalid("duplicate local hybrid key pair");
            }
        }
        return localByPair;
    }

    private static void requireProviderLength(
            byte[] value,
            int expectedLength,
            String description
    ) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalStateException(
                    description + " returned a non-" + expectedLength + "-byte public key"
            );
        }
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record KidPair(String x25519, String mlkem768) {
        private KidPair {
            if (x25519 == null || mlkem768 == null) {
                throw new IllegalArgumentException("hybrid kid pair values must not be null");
            }
        }
    }

    public record Match(
            PublicRecipient recipient,
            X25519PrivateKeyHandle x25519PrivateKey,
            MLKem768PrivateKeyHandle mlkem768PrivateKey
    ) {
        public Match {
            if (recipient == null || x25519PrivateKey == null || mlkem768PrivateKey == null) {
                throw new IllegalArgumentException("match values must not be null");
            }
        }
    }
}
