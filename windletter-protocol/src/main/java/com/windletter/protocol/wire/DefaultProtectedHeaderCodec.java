package com.windletter.protocol.wire;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Base64URL + JSON codec for outer protected header.
 */
public final class DefaultProtectedHeaderCodec implements ProtectedHeaderCodec {

    private final ObjectMapper objectMapper;

    /**
     * Create codec with default ObjectMapper.
     */
    public DefaultProtectedHeaderCodec() {
        this(new ObjectMapper());
    }

    /**
     * Create codec with caller-provided ObjectMapper.
     */
    public DefaultProtectedHeaderCodec(ObjectMapper objectMapper) {
        if (objectMapper == null) {
            throw new IllegalArgumentException("objectMapper must not be null");
        }
        this.objectMapper = objectMapper;
    }

    /**
     * Decode Base64URL protected payload into header object.
     */
    @Override
    public ProtectedHeader decode(String protectedB64) {
        if (protectedB64 == null || protectedB64.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "protected must not be blank");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(protectedB64);
            return objectMapper.readValue(new String(decoded, StandardCharsets.UTF_8), ProtectedHeader.class);
        } catch (IllegalArgumentException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "protected must be valid Base64URL JSON", e);
        } catch (JsonProcessingException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "protected must be decodable JSON", e);
        } catch (RuntimeException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "failed to decode protected header", e);
        }
    }

    /**
     * Encode header object into Base64URL protected payload.
     */
    @Override
    public String encode(ProtectedHeader header) {
        if (header == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "protected header must not be null");
        }
        try {
            byte[] jsonBytes = objectMapper.writeValueAsBytes(header);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(jsonBytes);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new ProtocolException(ErrorCode.MALFORMED_WIRE, "failed to encode protected header", e);
        }
    }
}
