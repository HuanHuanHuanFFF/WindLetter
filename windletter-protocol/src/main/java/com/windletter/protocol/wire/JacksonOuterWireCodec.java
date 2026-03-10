package com.windletter.protocol.wire;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;

/**
 * Jackson-based symmetric codec for outer wire payload.
 */
public final class JacksonOuterWireCodec implements OuterWireCodec {

    private final ObjectMapper objectMapper;

    /**
     * Create codec with default ObjectMapper.
     */
    public JacksonOuterWireCodec() {
        this(new ObjectMapper());
    }

    /**
     * Create codec with caller-provided ObjectMapper.
     */
    public JacksonOuterWireCodec(ObjectMapper objectMapper) {
        if (objectMapper == null) {
            throw new IllegalArgumentException("objectMapper must not be null");
        }
        this.objectMapper = objectMapper;
    }

    /**
     * Parse typed wire object only.
     */
    @Override
    public OuterWireMessage parse(String wireJson) {
        return parseWithRaw(wireJson).wire();
    }

    /**
     * Parse wire and keep raw recipients node from the same readTree result.
     */
    @Override
    public ParsedOuterWire parseWithRaw(String wireJson) {
        if (wireJson == null || wireJson.isBlank()) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "wireJson must not be blank");
        }
        try {
            JsonNode root = objectMapper.readTree(wireJson);
            if (root == null || !root.isObject()) {
                throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "outer wire root must be a JSON object");
            }
            JsonNode recipientsNode = root.get("recipients");
            OuterWireMessage wire = objectMapper.treeToValue(root, OuterWireMessage.class);
            return new ParsedOuterWire(wire, recipientsNode);
        } catch (ProtocolException e) {
            throw e;
        } catch (com.fasterxml.jackson.databind.DatabindException e) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "invalid wire field type or shape", e);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "failed to parse outer wire JSON", e);
        }
    }

    /**
     * Serialize typed wire object into JSON.
     */
    @Override
    public String serialize(OuterWireMessage wire) {
        if (wire == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "wire must not be null");
        }
        try {
            return objectMapper.writeValueAsString(wire);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "failed to serialize outer wire JSON", e);
        }
    }
}
