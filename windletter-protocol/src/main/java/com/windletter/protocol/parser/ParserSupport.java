package com.windletter.protocol.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.codec.Base64Url;

import java.util.Iterator;
import java.util.Set;

final class ParserSupport {

    static final String MODE_PUBLIC = "public";
    static final String MODE_OBFUSCATION = "obfuscation";
    static final String ALG_X25519 = "X25519";
    static final String ALG_HYBRID = "X25519ML-KEM-768";
    static final String CTY_WIND_JWS = "wind+jws";
    static final String CTY_WIND_INNER = "wind+inner";
    static final String TYP_WIND_JWE = "wind+jwe";
    static final String ENC_A256GCM = "A256GCM";
    static final String EPK_KTY_OKP = "OKP";
    static final String EPK_CRV_X25519 = "X25519";

    static final int LEN_GCM_IV = 12;
    static final int LEN_GCM_TAG = 16;
    static final int LEN_RID = 16;
    static final int LEN_X25519_PUB = 32;
    static final int LEN_KID = 32;
    static final int LEN_MLKEM768_CIPHERTEXT = 1088;
    static final int LEN_A256KW_WRAPPED_CEK = 40;

    private ParserSupport() {
    }

    static JsonNode parseJsonObject(ObjectMapper mapper, String json, String fieldPath) {
        JsonNode node;
        try {
            node = mapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw malformed(fieldPath + " is not valid JSON", e);
        }
        if (node == null || !node.isObject()) {
            throw malformed(fieldPath + " must be a JSON object");
        }
        return node;
    }

    static JsonNode requireObjectField(JsonNode parent, String fieldName, String parentPath) {
        JsonNode node = parent.get(fieldName);
        if (node == null) {
            throw invalidField(parentPath + "." + fieldName + " is required");
        }
        if (!node.isObject()) {
            throw malformed(parentPath + "." + fieldName + " must be a JSON object");
        }
        return node;
    }

    static void precheckOptionalArrayShape(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node != null && !node.isArray()) {
            throw malformed(fieldPath + " must be a JSON array");
        }
    }

    static void precheckOptionalObjectShape(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node != null && !node.isObject()) {
            throw malformed(fieldPath + " must be a JSON object");
        }
    }

    static void precheckOptionalTextShape(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node != null && !node.isTextual()) {
            throw malformed(fieldPath + " must be a JSON string");
        }
    }

    static void precheckOptionalBase64TextField(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node == null) {
            return;
        }
        if (!node.isTextual()) {
            throw malformed(fieldPath + " must be a JSON string");
        }
        String text = node.asText();
        if (text.isBlank()) {
            return;
        }
        decodeBase64UrlStrict(text, fieldPath);
    }

    static JsonNode requireArrayField(JsonNode parent, String fieldName, String parentPath) {
        JsonNode node = parent.get(fieldName);
        if (node == null) {
            throw invalidField(parentPath + "." + fieldName + " is required");
        }
        if (!node.isArray()) {
            throw malformed(parentPath + "." + fieldName + " must be a JSON array");
        }
        return node;
    }

    static void requireAbsent(JsonNode parent, String fieldName, String parentPath) {
        if (parent.has(fieldName)) {
            throw invalidField(parentPath + "." + fieldName + " must be absent");
        }
    }

    static void assertKnownFields(JsonNode objectNode, Set<String> allowedFields, String fieldPath) {
        Iterator<String> fields = objectNode.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (!allowedFields.contains(field)) {
                throw invalidField(fieldPath + "." + field + " is not allowed");
            }
        }
    }

    static String requireText(JsonNode parent, String fieldName, String parentPath) {
        JsonNode value = parent.get(fieldName);
        if (value == null) {
            throw invalidField(parentPath + "." + fieldName + " is required");
        }
        if (!value.isTextual()) {
            throw malformed(parentPath + "." + fieldName + " must be a JSON string");
        }
        String text = value.asText();
        if (text.isBlank()) {
            throw invalidField(parentPath + "." + fieldName + " must be a non-blank string");
        }
        return text;
    }

    static String optionalText(JsonNode parent, String fieldName, String parentPath) {
        JsonNode value = parent.get(fieldName);
        if (value == null) {
            return null;
        }
        if (!value.isTextual()) {
            throw malformed(parentPath + "." + fieldName + " must be a JSON string");
        }
        String text = value.asText();
        if (text.isBlank()) {
            throw invalidField(parentPath + "." + fieldName + " must be a non-blank string");
        }
        return text;
    }

    static String optionalTextRaw(JsonNode parent, String fieldName, String parentPath) {
        JsonNode value = parent.get(fieldName);
        if (value == null) {
            return null;
        }
        if (!value.isTextual()) {
            throw malformed(parentPath + "." + fieldName + " must be a JSON string");
        }
        return value.asText();
    }

    static byte[] decodeBase64UrlStrict(String value, String fieldPath) {
        return Base64Url.decodeCanonical(value, fieldPath);
    }

    static void requireLength(byte[] value, int expectedLength, String fieldPath) {
        if (value.length != expectedLength) {
            throw invalidField(fieldPath + " must decode to " + expectedLength + " bytes");
        }
    }

    static void requireMaxLength(byte[] value, int maxLength, String fieldPath) {
        if (value.length > maxLength) {
            throw invalidField(fieldPath + " must not exceed " + maxLength + " bytes");
        }
    }

    static ProtocolException malformed(String message) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message);
    }

    static ProtocolException malformed(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message, cause);
    }

    static ProtocolException unsupportedVersion(String message) {
        return new ProtocolException(ErrorCode.UNSUPPORTED_VERSION, message);
    }

    static ProtocolException unsupportedAlgorithm(String message) {
        return new ProtocolException(ErrorCode.UNSUPPORTED_ALGORITHM, message);
    }

    static ProtocolException invalidField(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    static ProtocolException internalError(String message) {
        return new ProtocolException(ErrorCode.INTERNAL_ERROR, message);
    }
}
