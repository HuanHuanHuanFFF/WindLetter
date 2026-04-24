package com.windletter.protocol;

import com.windletter.core.error.ErrorCode;

/**
 * Protocol-level exception with stable outward-facing error classification.
 */
public final class ProtocolException extends RuntimeException {

    private final ErrorCode errorCode;

    public ProtocolException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = requireErrorCode(errorCode);
    }

    public ProtocolException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = requireErrorCode(errorCode);
    }

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

