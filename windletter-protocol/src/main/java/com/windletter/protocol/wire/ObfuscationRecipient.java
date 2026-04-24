package com.windletter.protocol.wire;

import java.util.Arrays;

/**
 * Recipient entry for obfuscation mode.
 */
public record ObfuscationRecipient(byte[] rid, byte[] encryptedKey, byte[] ek) implements RecipientEntry {

    public ObfuscationRecipient {
        rid = WireChecks.copyBytes(rid, "rid");
        encryptedKey = WireChecks.copyBytes(encryptedKey, "encryptedKey");
        ek = WireChecks.copyNullableBytes(ek);
    }

    @Override
    public byte[] rid() {
        return Arrays.copyOf(rid, rid.length);
    }

    @Override
    public byte[] encryptedKey() {
        return Arrays.copyOf(encryptedKey, encryptedKey.length);
    }

    @Override
    public byte[] ek() {
        return WireChecks.copyNullableBytes(ek);
    }
}

