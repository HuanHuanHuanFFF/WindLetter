package com.windletter.protocol.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.windletter.core.encoding.Base64Url;
import org.erdtman.jcs.JsonCanonicalizer;

/**
 * JSON utilities for serialization and canonicalization.
 * JSON 序列化与规范化工具。
 */
public final class JsonUtil {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    private JsonUtil() {
    }

    public static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize JSON", e);
        }
    }

    public static <T> T fromJson(String json, Class<T> type) {
        try {
            return MAPPER.readValue(json, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JSON", e);
        }
    }

    public static String canonicalize(String json) {
        try {
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
            return canonicalizer.getEncodedString();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to canonicalize JSON", e);
        }
    }

    public static String canonicalize(Object value) {
        return canonicalize(toJson(value));
    }

    public static String canonicalizeAndEncode(Object value) {
        String canon = canonicalize(value);
        return Base64Url.encode(canon.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
