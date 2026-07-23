package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiPredicate;

/** Performs full-scan CEK recovery for obfuscation-mode Hybrid recipients. */
public final class ObfuscationHybridCekRecovery {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MLKEM768_PUBLIC_KEY_LENGTH = 1184;
    private static final int RID_LENGTH = 16;
    private static final int ENCAPSULATION_CIPHERTEXT_LENGTH = 1088;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final int CEK_LENGTH = 32;
    private static final String RECOVERY_FAILURE =
            "obfuscation hybrid recipient key recovery failed";

    private final ObfuscationHybridKeyDeriver keyDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final BiPredicate<byte[], byte[]> comparator;

    public ObfuscationHybridCekRecovery(
            ObfuscationHybridKeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap
    ) {
        this(keyDeriver, keyWrap, MessageDigest::isEqual);
    }

    ObfuscationHybridCekRecovery(
            ObfuscationHybridKeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap,
            BiPredicate<byte[], byte[]> comparator
    ) {
        if (keyDeriver == null) {
            throw new IllegalArgumentException("keyDeriver must not be null");
        }
        if (keyWrap == null) {
            throw new IllegalArgumentException("keyWrap must not be null");
        }
        if (comparator == null) {
            throw new IllegalArgumentException("comparator must not be null");
        }
        this.keyDeriver = keyDeriver;
        this.keyWrap = keyWrap;
        this.comparator = comparator;
    }

    public byte[] recover(
            Epk epk,
            List<RecipientEntry> recipients,
            List<ObfuscationHybridRecipientPrivateKeys> privateKeyPairs
    ) {
        byte[] epkX = null;
        List<WireRecipient> wire = new ArrayList<>();
        List<LocalPair> localPairs = new ArrayList<>();
        List<ObfuscationHybridKeyDeriver.ReceiverContext> contexts = new ArrayList<>();
        byte[] selectedKek = null;
        byte[] selectedWrapped = null;
        byte[] providerCek = null;
        try {
            epkX = validateAndCopyEpk(epk);
            validateAndFreezeWire(recipients, wire);
            rejectDuplicateWireRids(wire);
            freezeLocalPairs(privateKeyPairs, localPairs);
            boolean candidateCryptoFailed = openContexts(localPairs, epkX, contexts);

            int selectedWireIndex = -1;
            for (int wireIndex = 0; wireIndex < wire.size(); wireIndex++) {
                WireRecipient wireRecipient = wire.get(wireIndex);
                for (int localIndex = 0; localIndex < contexts.size(); localIndex++) {
                    ObfuscationHybridKeyDeriver.DerivedMaterial material = null;
                    byte[] candidateRid = null;
                    try {
                        try {
                            material = contexts.get(localIndex).deriveEntry(wireRecipient.ek());
                            if (material == null) {
                                throw new IllegalStateException(
                                        "Hybrid key derivation returned null material"
                                );
                            }
                            boolean failed = material.candidateCryptoFailed();
                            candidateCryptoFailed |= failed;
                            candidateRid = material.rid();
                            boolean matched = comparator.test(
                                    candidateRid,
                                    wireRecipient.rid()
                            );
                            if (selectedWireIndex < 0 && matched && !failed) {
                                selectedKek = material.kek();
                                selectedWireIndex = wireIndex;
                            }
                        } catch (RuntimeException failure) {
                            throw internal(
                                    "failed to derive Hybrid recipient candidate",
                                    failure
                            );
                        }
                    } finally {
                        clear(candidateRid);
                        if (material != null) {
                            material.close();
                        }
                    }
                }
            }

            if (candidateCryptoFailed) {
                throw keyRecoveryFailed();
            }
            if (selectedWireIndex < 0) {
                throw new ProtocolException(
                        ErrorCode.NOT_FOR_ME,
                        "no obfuscation Hybrid recipient matches local key pairs"
                );
            }

            selectedWrapped = wire.get(selectedWireIndex).encryptedKey().clone();
            try {
                providerCek = keyWrap.unwrap(selectedKek, selectedWrapped);
            } catch (CryptoOperationException failure) {
                throw keyRecoveryFailed();
            } catch (RuntimeException failure) {
                throw internal("A256KW provider failed to unwrap CEK", failure);
            }
            if (providerCek == null || providerCek.length != CEK_LENGTH) {
                throw internal("A256KW provider returned a non-32-byte CEK", null);
            }
            return providerCek.clone();
        } finally {
            clear(epkX);
            clear(selectedKek);
            clear(selectedWrapped);
            clear(providerCek);
            for (WireRecipient recipient : wire) {
                recipient.clear();
            }
            for (ObfuscationHybridKeyDeriver.ReceiverContext context : contexts) {
                context.close();
            }
            for (LocalPair localPair : localPairs) {
                localPair.clear();
            }
        }
    }

    private static byte[] validateAndCopyEpk(Epk epk) {
        if (epk == null || !"OKP".equals(epk.kty()) || !"X25519".equals(epk.crv())) {
            throw invalid("epk must use OKP/X25519");
        }
        byte[] epkX = epk.x();
        if (epkX == null || epkX.length != X25519_PUBLIC_KEY_LENGTH) {
            clear(epkX);
            throw invalid("epk.x must contain exactly 32 bytes");
        }
        return epkX;
    }

    private static void validateAndFreezeWire(
            List<RecipientEntry> recipients,
            List<WireRecipient> target
    ) {
        if (recipients == null || !isBucketSize(recipients.size())) {
            throw invalid(
                    "obfuscation Hybrid recipients must contain exactly 8, 16, or 32 entries"
            );
        }
        try {
            for (RecipientEntry entry : recipients) {
                if (!(entry instanceof ObfuscationRecipient recipient)) {
                    throw invalid(
                            "obfuscation Hybrid recipients must contain only obfuscation entries"
                    );
                }
                byte[] rid = recipient.rid();
                byte[] encryptedKey = recipient.encryptedKey();
                byte[] ek = recipient.ek();
                boolean stored = false;
                try {
                    if (rid.length != RID_LENGTH
                            || encryptedKey.length != WRAPPED_CEK_LENGTH
                            || ek == null
                            || ek.length != ENCAPSULATION_CIPHERTEXT_LENGTH) {
                        throw invalid("invalid obfuscation Hybrid recipient entry");
                    }
                    target.add(new WireRecipient(rid, encryptedKey, ek));
                    stored = true;
                } finally {
                    if (!stored) {
                        clear(rid);
                        clear(encryptedKey);
                        clear(ek);
                    }
                }
            }
        } catch (RuntimeException failure) {
            for (WireRecipient recipient : target) {
                recipient.clear();
            }
            target.clear();
            throw failure;
        }
    }

    private static void rejectDuplicateWireRids(List<WireRecipient> wire) {
        for (int current = 0; current < wire.size(); current++) {
            for (int previous = 0; previous < current; previous++) {
                if (MessageDigest.isEqual(
                        wire.get(current).rid(),
                        wire.get(previous).rid()
                )) {
                    throw invalid("duplicate obfuscation Hybrid recipient rid");
                }
            }
        }
    }

    private static void freezeLocalPairs(
            List<ObfuscationHybridRecipientPrivateKeys> privateKeyPairs,
            List<LocalPair> target
    ) {
        if (privateKeyPairs == null) {
            throw internal("local Hybrid private-key pairs must not be null", null);
        }
        final List<ObfuscationHybridRecipientPrivateKeys> snapshot;
        try {
            snapshot = new ArrayList<>(privateKeyPairs);
        } catch (RuntimeException failure) {
            throw internal("failed to snapshot local Hybrid private-key pairs", failure);
        }

        for (ObfuscationHybridRecipientPrivateKeys pair : snapshot) {
            if (pair == null) {
                throw internal("local Hybrid private-key pairs must not contain null", null);
            }
            byte[] x25519PublicKey = null;
            byte[] mlkem768PublicKey = null;
            boolean stored = false;
            try {
                try {
                    x25519PublicKey = pair.x25519PrivateKey().publicKey();
                } catch (RuntimeException failure) {
                    throw internal("failed to inspect local X25519 key handle", failure);
                }
                if (x25519PublicKey == null
                        || x25519PublicKey.length != X25519_PUBLIC_KEY_LENGTH) {
                    throw internal(
                            "local X25519 handle returned a non-32-byte public key",
                            null
                    );
                }

                try {
                    mlkem768PublicKey = pair.mlkem768PrivateKey().publicKey();
                } catch (RuntimeException failure) {
                    throw internal("failed to inspect local ML-KEM-768 key handle", failure);
                }
                if (mlkem768PublicKey == null
                        || mlkem768PublicKey.length != MLKEM768_PUBLIC_KEY_LENGTH) {
                    throw internal(
                            "local ML-KEM-768 handle returned a non-1184-byte public key",
                            null
                    );
                }

                if (containsPair(target, x25519PublicKey, mlkem768PublicKey)) {
                    throw internal("duplicate local Hybrid private-key pair", null);
                }
                target.add(new LocalPair(
                        pair,
                        x25519PublicKey,
                        mlkem768PublicKey
                ));
                stored = true;
            } finally {
                if (!stored) {
                    clear(x25519PublicKey);
                    clear(mlkem768PublicKey);
                }
            }
        }
    }

    private static boolean containsPair(
            List<LocalPair> localPairs,
            byte[] x25519PublicKey,
            byte[] mlkem768PublicKey
    ) {
        for (LocalPair localPair : localPairs) {
            if (MessageDigest.isEqual(localPair.x25519PublicKey(), x25519PublicKey)
                    && MessageDigest.isEqual(
                    localPair.mlkem768PublicKey(),
                    mlkem768PublicKey
            )) {
                return true;
            }
        }
        return false;
    }

    private boolean openContexts(
            List<LocalPair> localPairs,
            byte[] epkX,
            List<ObfuscationHybridKeyDeriver.ReceiverContext> target
    ) {
        boolean candidateCryptoFailed = false;
        for (LocalPair localPair : localPairs) {
            try {
                ObfuscationHybridKeyDeriver.ReceiverContext context =
                        keyDeriver.openForReceiver(
                                localPair.keys().x25519PrivateKey(),
                                localPair.keys().mlkem768PrivateKey(),
                                epkX
                        );
                if (context == null) {
                    throw new IllegalStateException(
                            "Hybrid key derivation returned a null receiver context"
                    );
                }
                target.add(context);
                candidateCryptoFailed |= context.candidateCryptoFailed();
            } catch (RuntimeException failure) {
                throw internal("failed to open Hybrid receiver context", failure);
            }
        }
        return candidateCryptoFailed;
    }

    private static boolean isBucketSize(int size) {
        return size == 8 || size == 16 || size == 32;
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.INTERNAL_ERROR, message)
                : new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static ProtocolException keyRecoveryFailed() {
        return new ProtocolException(ErrorCode.KEY_UNWRAP_FAILED, RECOVERY_FAILURE);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record WireRecipient(byte[] rid, byte[] encryptedKey, byte[] ek) {
        private void clear() {
            ObfuscationHybridCekRecovery.clear(rid);
            ObfuscationHybridCekRecovery.clear(encryptedKey);
            ObfuscationHybridCekRecovery.clear(ek);
        }
    }

    private record LocalPair(
            ObfuscationHybridRecipientPrivateKeys keys,
            byte[] x25519PublicKey,
            byte[] mlkem768PublicKey
    ) {
        private void clear() {
            ObfuscationHybridCekRecovery.clear(x25519PublicKey);
            ObfuscationHybridCekRecovery.clear(mlkem768PublicKey);
        }
    }
}
