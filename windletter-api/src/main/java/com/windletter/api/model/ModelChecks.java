package com.windletter.api.model;

import java.util.List;
import java.util.Map;

/**
 * Internal validation helpers for the model package.
 * <p>
 * Throws {@link IllegalArgumentException} consistently for stable parameter-error handling.
 */
final class ModelChecks {

    private ModelChecks() {
    }

    /**
     * Require field to be non-null.
     */
    static <T> T requireNonNull(T value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    /**
     * Require string to be non-blank.
     */
    static String requireNonBlank(String value, String field) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    /**
     * Copy and freeze list, and require non-empty.
     */
    static <T> List<T> copyNonEmptyList(List<T> input, String field) {
        requireNonNull(input, field);
        if (input.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be empty");
        }
        return List.copyOf(input);
    }

    /**
     * Copy and freeze map; return empty map when null.
     */
    static <K, V> Map<K, V> copyMap(Map<K, V> input) {
        return input == null ? Map.of() : Map.copyOf(input);
    }

    /**
     * Blank check (null/empty/blank).
     */
    static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
