package com.windletter.protocol.wire;

import java.util.Arrays;
import java.util.List;

/**
 * Parsed and validated outer wire payload.
 */
public record WindLetter(
        ProtectedHeader protectedHeader,
        String protectedValue,
        String aad,
        List<RecipientEntry> recipients,
        byte[] iv,
        byte[] ciphertext,
        byte[] tag
) {

    public WindLetter {
        protectedHeader = WireChecks.requireNonNull(protectedHeader, "protectedHeader");
        protectedValue = WireChecks.requireNonBlank(protectedValue, "protectedValue");
        aad = WireChecks.requireNonBlank(aad, "aad");
        recipients = WireChecks.copyNonEmptyList(recipients, "recipients");
        iv = WireChecks.copyBytes(iv, "iv");
        ciphertext = WireChecks.copyBytes(ciphertext, "ciphertext");
        tag = WireChecks.copyBytes(tag, "tag");
    }

    @Override
    public byte[] iv() {
        return Arrays.copyOf(iv, iv.length);
    }

    @Override
    public byte[] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public byte[] tag() {
        return Arrays.copyOf(tag, tag.length);
    }
}
