package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiPredicate;

/** Recovers an obfuscation-mode content-encryption key from local X25519 keys. */
public final class ObfuscationX25519CekRecovery {

    private static final int X25519_LENGTH = 32;
    private static final int RID_LENGTH = 16;
    private static final int WRAPPED_CEK_LENGTH = 40;
    private static final String UNWRAP_FAILURE = "obfuscation recipient key recovery failed";

    private final ObfuscationX25519KeyDeriver keyDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final BiPredicate<byte[], byte[]> comparator;

    public ObfuscationX25519CekRecovery(
            ObfuscationX25519KeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap
    ) {
        this(keyDeriver, keyWrap, MessageDigest::isEqual);
    }

    ObfuscationX25519CekRecovery(
            ObfuscationX25519KeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap,
            BiPredicate<byte[], byte[]> comparator
    ) {
        if (keyDeriver == null || keyWrap == null || comparator == null) {
            throw new IllegalArgumentException("keyDeriver, keyWrap, and comparator must not be null");
        }
        this.keyDeriver = keyDeriver;
        this.keyWrap = keyWrap;
        this.comparator = comparator;
    }

    public byte[] recover(
            Epk epk,
            List<RecipientEntry> recipients,
            List<X25519PrivateKeyHandle> privateKeys
    ) {
        byte[] epkX = null;
        List<WireRecipient> wire = new ArrayList<>();
        List<LocalMaterial> local = new ArrayList<>();
        byte[] providerCek = null;
        byte[] selectedWrapped = null;
        try {
            epkX = validateAndCopyEpk(epk);
            validateAndFreezeWire(recipients, wire);
            rejectDuplicateWireRids(wire);
            freezeLocalMaterials(privateKeys, epkX, local);

            Selection selection = select(wire, local);
            if (selection == null) {
                throw new ProtocolException(ErrorCode.NOT_FOR_ME,
                        "no obfuscation recipient matches local keys");
            }
            selectedWrapped = wire.get(selection.wireIndex()).encryptedKey().clone();
            try {
                providerCek = keyWrap.unwrap(local.get(selection.localIndex()).kek(), selectedWrapped);
            } catch (CryptoOperationException e) {
                throw keyUnwrapFailed();
            } catch (RuntimeException e) {
                throw internal("A256KW provider failed to unwrap CEK", e);
            }
            if (providerCek == null || providerCek.length != X25519_LENGTH) {
                throw keyUnwrapFailed();
            }
            return providerCek.clone();
        } finally {
            clear(epkX);
            clear(providerCek);
            clear(selectedWrapped);
            for (WireRecipient entry : wire) {
                entry.clear();
            }
            for (LocalMaterial entry : local) {
                entry.close();
            }
        }
    }

    private byte[] validateAndCopyEpk(Epk epk) {
        if (epk == null || !"OKP".equals(epk.kty()) || !"X25519".equals(epk.crv())) {
            throw invalid("epk must use OKP/X25519");
        }
        byte[] x = epk.x();
        try {
            if (x == null || x.length != X25519_LENGTH) {
                throw invalid("epk.x must contain exactly 32 bytes");
            }
            return x.clone();
        } finally {
            clear(x);
        }
    }

    private static void validateAndFreezeWire(List<RecipientEntry> recipients, List<WireRecipient> target) {
        if (recipients == null || (recipients.size() != 8 && recipients.size() != 16 && recipients.size() != 32)) {
            throw invalid("obfuscation recipients must contain exactly 8, 16, or 32 entries");
        }
        try {
            for (RecipientEntry entry : recipients) {
                if (!(entry instanceof ObfuscationRecipient recipient)) {
                    throw invalid("obfuscation recipients must contain only obfuscation entries");
                }
                byte[] rid = recipient.rid();
                byte[] encrypted = recipient.encryptedKey();
                byte[] ek = recipient.ek();
                try {
                    if (rid.length != RID_LENGTH || encrypted.length != WRAPPED_CEK_LENGTH || ek != null) {
                        throw invalid("invalid obfuscation recipient entry");
                    }
                    target.add(new WireRecipient(rid.clone(), encrypted.clone()));
                } finally {
                    clear(rid); clear(encrypted); clear(ek);
                }
            }
        } catch (RuntimeException e) {
            for (WireRecipient entry : target) entry.clear();
            target.clear();
            throw e;
        }
    }

    private static void rejectDuplicateWireRids(List<WireRecipient> wire) {
        for (int i = 0; i < wire.size(); i++) {
            for (int j = 0; j < i; j++) {
                if (MessageDigest.isEqual(wire.get(i).rid(), wire.get(j).rid())) {
                    throw invalid("duplicate obfuscation recipient rid");
                }
            }
        }
    }

    private void freezeLocalMaterials(
            List<X25519PrivateKeyHandle> privateKeys,
            byte[] epkX,
            List<LocalMaterial> target
    ) {
        if (privateKeys == null) {
            throw internal("local X25519 private-key handles must not be null", null);
        }
        final List<X25519PrivateKeyHandle> keySnapshot;
        try {
            keySnapshot = new ArrayList<>(privateKeys);
        } catch (RuntimeException e) {
            throw internal("failed to snapshot local X25519 key handles", e);
        }
        List<byte[]> publicKeys = new ArrayList<>();
        try {
            for (X25519PrivateKeyHandle handle : keySnapshot) {
                if (handle == null) throw internal("local X25519 private-key handles must not contain null", null);
                byte[] publicKey;
                try {
                    publicKey = handle.publicKey();
                } catch (RuntimeException e) {
                    throw internal("failed to inspect local X25519 key handle", e);
                }
                if (publicKey == null || publicKey.length != X25519_LENGTH) {
                    clear(publicKey);
                    throw internal("local X25519 handle returned a non-32-byte public key", null);
                }
                for (byte[] seen : publicKeys) {
                    if (MessageDigest.isEqual(seen, publicKey)) {
                        clear(publicKey);
                        throw internal("duplicate local X25519 public key", null);
                    }
                }
                publicKeys.add(publicKey);
            }
            for (X25519PrivateKeyHandle handle : keySnapshot) {
                try {
                    ObfuscationX25519KeyDeriver.DerivedMaterial material = keyDeriver.derive(handle, epkX);
                    if (material == null) throw internal("X25519 key derivation returned null", null);
                    byte[] rid = material.rid();
                    byte[] kek = material.kek();
                    target.add(new LocalMaterial(material, rid, kek));
                } catch (CryptoOperationException e) {
                    throw keyUnwrapFailed();
                } catch (ProtocolException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw internal("failed to derive local obfuscation recipient material", e);
                }
            }
        } finally {
            for (byte[] publicKey : publicKeys) clear(publicKey);
        }
    }

    private Selection select(List<WireRecipient> wire, List<LocalMaterial> local) {
        Selection selected = null;
        for (int wireIndex = 0; wireIndex < wire.size(); wireIndex++) {
            for (int localIndex = 0; localIndex < local.size(); localIndex++) {
                if (comparator.test(local.get(localIndex).rid(), wire.get(wireIndex).rid())) {
                    if (selected == null) selected = new Selection(wireIndex, localIndex);
                }
            }
        }
        return selected;
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.INTERNAL_ERROR, message)
                : new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static ProtocolException keyUnwrapFailed() {
        return new ProtocolException(ErrorCode.KEY_UNWRAP_FAILED, UNWRAP_FAILURE);
    }

    private static void clear(byte[] value) { if (value != null) Arrays.fill(value, (byte) 0); }

    private record Selection(int wireIndex, int localIndex) { }

    private record WireRecipient(byte[] rid, byte[] encryptedKey) {
        private void clear() { ObfuscationX25519CekRecovery.clear(rid); ObfuscationX25519CekRecovery.clear(encryptedKey); }
    }

    private static final class LocalMaterial {
        private final ObfuscationX25519KeyDeriver.DerivedMaterial material;
        private final byte[] rid;
        private final byte[] kek;
        private LocalMaterial(ObfuscationX25519KeyDeriver.DerivedMaterial material, byte[] rid, byte[] kek) {
            this.material = material; this.rid = rid; this.kek = kek;
        }
        private byte[] rid() { return rid; }
        private byte[] kek() { return kek; }
        private void close() { clear(rid); clear(kek); material.close(); }
    }
}
