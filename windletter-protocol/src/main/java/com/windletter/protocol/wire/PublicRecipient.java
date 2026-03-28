package com.windletter.protocol.wire;

import java.util.Arrays;

/**
 * Recipient entry for public mode.
 */
public record PublicRecipient(RecipientKid kid, byte[] encryptedKey, byte[] ek) implements RecipientEntry {

    public PublicRecipient {
        kid = WireChecks.requireNonNull(kid, "kid");
        encryptedKey = WireChecks.copyBytes(encryptedKey, "encryptedKey");
        ek = WireChecks.copyNullableBytes(ek);
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

