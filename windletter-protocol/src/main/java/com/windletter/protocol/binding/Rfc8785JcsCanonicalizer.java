package com.windletter.protocol.binding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * RFC 8785 canonicalizer based on java-json-canonicalization library.
 */
public final class Rfc8785JcsCanonicalizer implements JcsCanonicalizer {

    private final ObjectMapper objectMapper;

    /**
     * Create canonicalizer with default ObjectMapper.
     */
    public Rfc8785JcsCanonicalizer() {
        this(new ObjectMapper());
    }

    /**
     * Create canonicalizer with caller-provided ObjectMapper.
     */
    public Rfc8785JcsCanonicalizer(ObjectMapper objectMapper) {
        if (objectMapper == null) {
            throw new IllegalArgumentException("objectMapper must not be null");
        }
        this.objectMapper = objectMapper;
    }

    /**
     * Canonicalize input value into RFC 8785 JSON bytes.
     */
    @Override
    public byte[] canonicalize(Object value) {
        if (value == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        try {
            String rawJson = objectMapper.writeValueAsString(value);
            String canonicalized = new JsonCanonicalizer(rawJson).getEncodedString();
            return canonicalized.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("failed to serialize value for canonicalization", e);
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("failed to canonicalize JSON value", e);
        }
    }
}
