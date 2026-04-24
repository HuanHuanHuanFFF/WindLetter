package com.windletter.protocol.wire;

import java.util.Arrays;
import java.util.List;

final class WireChecks {

    private WireChecks() {
    }

    static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }

    static <T> T requireNonNull(T value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " must not be null");
        }
        return value;
    }

    static byte[] copyBytes(byte[] value, String fieldName) {
        requireNonNull(value, fieldName);
        return Arrays.copyOf(value, value.length);
    }

    static byte[] copyNullableBytes(byte[] value) {
        if (value == null) {
            return null;
        }
        return Arrays.copyOf(value, value.length);
    }

    static <T> List<T> copyList(List<T> value, String fieldName) {
        requireNonNull(value, fieldName);
        return List.copyOf(value);
    }
}
