package com.windletter.protocol.inner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.ProtocolLimits;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.StrictJson;
import com.windletter.protocol.model.ProtocolPayload;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Strict codec for the direct, unsigned WindLetter inner object.
 */
public final class UnsignedInnerCodec {

    private static final ObjectMapper STRICT_JSON = StrictJson.newMapper();
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final int SHA_256_BYTES = 32;
    private static final String INNER_TYPE = "wind+inner";
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private static final Set<String> ROOT_FIELDS = Set.of("protected", "payload");
    private static final Set<String> PROTECTED_FIELDS = Set.of(
            "typ", "ts", "wind_id", "jwe_protected_hash", "jwe_recipients_hash"
    );
    private static final Set<String> PAYLOAD_FIELDS = Set.of("meta", "body");
    private static final Set<String> META_FIELDS = Set.of("content_type", "original_size");
    private static final Set<String> BODY_FIELDS = Set.of("data");

    public byte[] encode(Message message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }

        ObjectNode protectedNode = JsonNodeFactory.instance.objectNode();
        protectedNode.put("typ", INNER_TYPE);
        protectedNode.put("ts", message.timestamp());
        protectedNode.put("wind_id", message.messageId());
        protectedNode.put("jwe_protected_hash", Base64Url.encode(message.binding().protectedHash()));
        protectedNode.put("jwe_recipients_hash", Base64Url.encode(message.binding().recipientsHash()));

        ProtocolPayload payload = message.payload();
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("content_type", payload.contentType());
        meta.put("original_size", payload.originalSize());

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("data", Base64Url.encode(payload.data()));

        ObjectNode payloadNode = JsonNodeFactory.instance.objectNode();
        payloadNode.set("meta", meta);
        payloadNode.set("body", body);

        ObjectNode root = JsonNodeFactory.instance.objectNode();
        root.set("protected", protectedNode);
        root.set("payload", payloadNode);

        byte[] encoded = JcsCanonicalizer.canonicalize(root);
        if (encoded.length > ProtocolLimits.MAX_INNER_BYTES) {
            throw new IllegalArgumentException("encoded inner message exceeds the supported size");
        }
        return encoded;
    }

    public Message decode(byte[] innerBytes) {
        if (innerBytes == null) {
            throw malformed("inner bytes must not be null");
        }
        if (innerBytes.length > ProtocolLimits.MAX_INNER_BYTES) {
            throw invalid("inner message exceeds the supported size");
        }

        JsonNode parsed;
        try {
            parsed = STRICT_JSON.readTree(innerBytes);
        } catch (IOException | RuntimeException e) {
            if (e instanceof ProtocolException protocolException) {
                throw protocolException;
            }
            throw malformed("inner message is not strict UTF-8 JSON", e);
        }

        ObjectNode root = requireObject(parsed, "inner");
        requireExactFields(root, ROOT_FIELDS, "inner");

        ObjectNode protectedNode = requireObject(root.get("protected"), "inner.protected");
        requireExactFields(protectedNode, PROTECTED_FIELDS, "inner.protected");
        String typ = requireText(protectedNode.get("typ"), "inner.protected.typ");
        if (!INNER_TYPE.equals(typ)) {
            throw invalid("inner.protected.typ must be wind+inner");
        }

        long timestamp = requireIntegralLong(protectedNode.get("ts"), "inner.protected.ts");
        if (!validTimestamp(timestamp)) {
            throw invalid("inner.protected.ts is outside the supported range");
        }

        String messageId = requireText(protectedNode.get("wind_id"), "inner.protected.wind_id");
        if (!validMessageId(messageId)) {
            throw invalid("inner.protected.wind_id must be a canonical lowercase UUID v4");
        }

        byte[] protectedHash = decodeHash(
                protectedNode.get("jwe_protected_hash"), "inner.protected.jwe_protected_hash"
        );
        byte[] recipientsHash = decodeHash(
                protectedNode.get("jwe_recipients_hash"), "inner.protected.jwe_recipients_hash"
        );

        ObjectNode payloadNode = requireObject(root.get("payload"), "inner.payload");
        requireExactFields(payloadNode, PAYLOAD_FIELDS, "inner.payload");
        ObjectNode meta = requireObject(payloadNode.get("meta"), "inner.payload.meta");
        requireExactFields(meta, META_FIELDS, "inner.payload.meta");
        ObjectNode body = requireObject(payloadNode.get("body"), "inner.payload.body");
        requireExactFields(body, BODY_FIELDS, "inner.payload.body");

        String contentType = requireText(meta.get("content_type"), "inner.payload.meta.content_type");
        if (contentType.isBlank()) {
            throw invalid("inner.payload.meta.content_type must be non-blank");
        }
        long originalSize = requireIntegralLong(meta.get("original_size"), "inner.payload.meta.original_size");
        if (originalSize < 0 || originalSize > ProtocolLimits.MAX_PAYLOAD_BYTES) {
            throw invalid("inner.payload.meta.original_size is outside the supported range");
        }

        String dataValue = requireText(body.get("data"), "inner.payload.body.data");
        byte[] data = Base64Url.decodeCanonicalAllowEmpty(dataValue, "inner.payload.body.data");
        if (data.length > ProtocolLimits.MAX_PAYLOAD_BYTES) {
            throw invalid("inner.payload.body.data exceeds the supported size");
        }
        if (originalSize != data.length) {
            throw invalid("inner.payload.meta.original_size does not match decoded data");
        }

        return new Message(
                messageId,
                timestamp,
                new ProtocolPayload(contentType, data, originalSize),
                new OuterBinding.Hashes(protectedHash, recipientsHash)
        );
    }

    private static byte[] decodeHash(JsonNode node, String fieldPath) {
        String encoded = requireText(node, fieldPath);
        byte[] decoded = Base64Url.decodeCanonical(encoded, fieldPath);
        if (decoded.length != SHA_256_BYTES) {
            throw invalid(fieldPath + " must decode to exactly 32 bytes");
        }
        return decoded;
    }

    private static ObjectNode requireObject(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isObject()) {
            throw malformed(fieldPath + " must be a non-null object");
        }
        return (ObjectNode) node;
    }

    private static String requireText(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isTextual()) {
            throw malformed(fieldPath + " must be a non-null string");
        }
        return node.textValue();
    }

    private static long requireIntegralLong(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isNumber()) {
            throw malformed(fieldPath + " must be a non-null number");
        }
        if (!node.isIntegralNumber() || !node.canConvertToLong()) {
            throw invalid(fieldPath + " must be represented as an integral JSON number");
        }
        return node.longValue();
    }

    private static void requireExactFields(ObjectNode node, Set<String> expected, String fieldPath) {
        node.fieldNames().forEachRemaining(name -> {
            if (!expected.contains(name)) {
                throw invalid(fieldPath + " contains unknown or disallowed field: " + name);
            }
        });
        for (String name : expected) {
            if (!node.has(name)) {
                throw invalid(fieldPath + " is missing required field: " + name);
            }
        }
    }

    private static boolean validTimestamp(long timestamp) {
        return timestamp >= 0 && timestamp <= MAX_SAFE_JSON_INTEGER;
    }

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) {
            return false;
        }
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4 && uuid.variant() == 2 && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static ProtocolException malformed(String message) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message);
    }

    private static ProtocolException malformed(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message, cause);
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    public record Message(
            String messageId,
            long timestamp,
            ProtocolPayload payload,
            OuterBinding.Hashes binding
    ) {
        public Message {
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException("messageId must be a canonical lowercase UUID v4");
            }
            if (!validTimestamp(timestamp)) {
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (binding == null) {
                throw new IllegalArgumentException("binding must not be null");
            }
        }
    }
}
