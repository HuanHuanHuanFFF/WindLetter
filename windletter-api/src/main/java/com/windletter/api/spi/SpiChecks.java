package com.windletter.api.spi;

import java.util.Map;

/**
 * spi 包内部校验工具。
 */
final class SpiChecks {

    private SpiChecks() {
    }

    /**
     * 要求字符串非空白。
     */
    static String requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    /**
     * 复制并冻结 map，null 时返回空 map。
     */
    static <K, V> Map<K, V> copyMap(Map<K, V> input) {
        return input == null ? Map.of() : Map.copyOf(input);
    }
}
