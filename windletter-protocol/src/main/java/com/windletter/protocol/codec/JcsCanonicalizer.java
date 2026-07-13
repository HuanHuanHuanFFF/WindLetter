package com.windletter.protocol.codec;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;

/**
 * RFC 8785 JSON Canonicalization Scheme encoder.
 */
public final class JcsCanonicalizer {

    private JcsCanonicalizer() {
    }

    public static byte[] canonicalize(JsonNode value) {
        if (value == null) {
            throw new IllegalArgumentException("value must not be null");
        }

        try {
            return new org.erdtman.jcs.JsonCanonicalizer(value.toString()).getEncodedUTF8();
        } catch (IOException e) {
            throw new IllegalStateException("failed to canonicalize JSON", e);
        }
    }
}
