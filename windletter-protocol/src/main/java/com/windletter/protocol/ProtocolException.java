package com.windletter.protocol;

import com.windletter.core.error.ErrorCode;

/**
 * Protocol-layer exception carrying stable outward-facing error code.
 */
public final class ProtocolException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * Create protocol exception with stable error code.
     */
    public ProtocolException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = requireErrorCode(errorCode);
    }

    /**
     * Create protocol exception with stable error code and cause.
     */
    public ProtocolException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = requireErrorCode(errorCode);
    }

    /**
     * Get stable outward-facing error code.
     */
    public ErrorCode errorCode() {
        return errorCode;
    }

    private static ErrorCode requireErrorCode(ErrorCode errorCode) {
        if (errorCode == null) {
            throw new IllegalArgumentException("errorCode must not be null");
        }
        return errorCode;
    }
}
