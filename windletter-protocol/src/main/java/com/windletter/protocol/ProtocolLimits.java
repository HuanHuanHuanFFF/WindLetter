package com.windletter.protocol;

/**
 * Resource limits enforced by the WindLetter v1.0 demo implementation.
 */
public final class ProtocolLimits {

    public static final int MAX_JSON_DEPTH = 32;
    public static final int MAX_RECIPIENTS = 32;
    public static final int MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
    public static final int MAX_INNER_BYTES = 12 * 1024 * 1024;
    public static final int MAX_CIPHERTEXT_BYTES = 12 * 1024 * 1024;
    public static final int MAX_WIRE_UTF8_BYTES = 20 * 1024 * 1024;

    private ProtocolLimits() {
    }
}
