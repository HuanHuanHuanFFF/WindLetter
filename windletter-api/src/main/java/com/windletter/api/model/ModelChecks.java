package com.windletter.api.model;

import java.util.List;
import java.util.Map;

/**
 * model 包内部校验工具。
 * <p>
 * 统一抛出 {@link IllegalArgumentException}，便于调用方稳定处理参数错误。
 */
final class ModelChecks {

    private ModelChecks() {
    }

    /**
     * 要求字段非 null。
     */
    static <T> T requireNonNull(T value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    /**
     * 要求字符串非空白。
     */
    static String requireNonBlank(String value, String field) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    /**
     * 复制并冻结 list，同时要求非空。
     */
    static <T> List<T> copyNonEmptyList(List<T> input, String field) {
        requireNonNull(input, field);
        if (input.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be empty");
        }
        return List.copyOf(input);
    }

    /**
     * 复制并冻结 map，null 时返回空 map。
     */
    static <K, V> Map<K, V> copyMap(Map<K, V> input) {
        return input == null ? Map.of() : Map.copyOf(input);
    }

    /**
     * 判空白（null/empty/blank）。
     */
    static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
