package com.windletter.crypto.api;

/**
 * Exception for cryptographic operation failures.
 * <p>
 * Wraps implementation-specific exceptions from underlying crypto libraries and exposes stable semantics to upper layers.
 */
public class CryptoOperationException extends RuntimeException {

    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
