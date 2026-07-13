package com.windletter.protocol.model;

import com.windletter.protocol.ProtocolLimits;

import java.util.Arrays;

/**
 * Decrypted WindLetter payload bytes and their protocol metadata.
 */
public record ProtocolPayload(String contentType, byte[] data, long originalSize) {

    public ProtocolPayload {
        if (contentType == null || contentType.isBlank()) {
            throw new IllegalArgumentException("contentType must be non-blank");
        }
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }
        if (originalSize < 0 || originalSize > ProtocolLimits.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("originalSize is outside the supported payload range");
        }
        if (originalSize != data.length) {
            throw new IllegalArgumentException("originalSize must equal the payload byte length");
        }
        data = Arrays.copyOf(data, data.length);
    }

    @Override
    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }
}
