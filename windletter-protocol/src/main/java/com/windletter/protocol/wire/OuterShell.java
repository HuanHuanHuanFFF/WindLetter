package com.windletter.protocol.wire;

import java.util.Arrays;

/**
 * Outer fixed transport fields.
 */
public record OuterShell(
        String protectedValue,
        String aad,
        byte[] iv,
        byte[] ciphertext,
        byte[] tag
) {

    public OuterShell {
        protectedValue = WireChecks.requireNonBlank(protectedValue, "protectedValue");
        aad = WireChecks.requireNonBlank(aad, "aad");
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

