package com.windletter.protocol.derivation;

import java.util.Arrays;

/**
 * Immutable derivation spec for protocol-level KEK/rid material.
 */
public record KekDerivationSpec(String id, byte[] salt, byte[] info, int inputLength, int outputLength) {

    public KekDerivationSpec {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (salt == null) {
            throw new IllegalArgumentException("salt must not be null");
        }
        if (info == null) {
            throw new IllegalArgumentException("info must not be null");
        }
        if (inputLength <= 0) {
            throw new IllegalArgumentException("inputLength must be > 0");
        }
        if (outputLength <= 0) {
            throw new IllegalArgumentException("outputLength must be > 0");
        }
        salt = Arrays.copyOf(salt, salt.length);
        info = Arrays.copyOf(info, info.length);
    }

    @Override
    public byte[] salt() {
        return Arrays.copyOf(salt, salt.length);
    }

    @Override
    public byte[] info() {
        return Arrays.copyOf(info, info.length);
    }
}
