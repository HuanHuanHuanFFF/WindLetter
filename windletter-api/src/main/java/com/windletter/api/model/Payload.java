package com.windletter.api.model;

import java.util.Arrays;

/**
 * Business payload.
 *
 * @param contentType MIME type
 * @param data raw byte data
 * @param originalSize original size, which must equal the data length
 */
public record Payload(String contentType, byte[] data, long originalSize) {

    /**
     * Canonical constructor with payload-field validation and defensive copy.
     *
     * @throws IllegalArgumentException if contentType/data/originalSize is invalid
     */
    public Payload {
        contentType = ModelChecks.requireNonBlank(contentType, "contentType");
        ModelChecks.requireNonNull(data, "data");
        if (originalSize != data.length) {
            throw new IllegalArgumentException("originalSize must equal data length");
        }
        data = Arrays.copyOf(data, data.length);
    }

    /**
     * Returns a copy of data to prevent external mutation of internal state.
     */
    @Override
    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }
}
