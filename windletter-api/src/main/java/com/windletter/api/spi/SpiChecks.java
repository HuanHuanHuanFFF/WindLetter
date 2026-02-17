package com.windletter.api.spi;

import java.util.Map;

/**
 * Internal validation helpers for the spi package.
 */
final class SpiChecks {

    private SpiChecks() {
    }

    /**
     * Require string to be non-blank.
     */
    static String requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    /**
     * Copy and freeze map; return empty map when null.
     */
    static <K, V> Map<K, V> copyMap(Map<K, V> input) {
        return input == null ? Map.of() : Map.copyOf(input);
    }
}
