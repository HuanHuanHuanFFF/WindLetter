package com.windletter.api.enums;

/**
 * Overall decryption status.
 */
public enum DecryptStatus {
    /** Successfully decrypted and produced payload. */
    SUCCESS,
    /** Message is not for the current receiver. */
    NOT_FOR_ME,
    /** Message structure or authentication validation failed. */
    INVALID_MESSAGE,
    /** Version or algorithm is not supported. */
    UNSUPPORTED
}
