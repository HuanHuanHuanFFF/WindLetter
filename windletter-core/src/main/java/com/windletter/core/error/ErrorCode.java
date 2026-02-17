package com.windletter.core.error;

/**
 * Stable outward-facing error codes.
 * <p>
 * This enum is the shared contract between API and implementation layers; additions should remain backward compatible.
 */
public enum ErrorCode {
    /** Wire structure or JSON shape is invalid. */
    MALFORMED_WIRE,
    /** Protocol version is not supported. */
    UNSUPPORTED_VERSION,
    /** Algorithm or algorithm combination is not supported. */
    UNSUPPORTED_ALGORITHM,
    /** Message is not addressed to the current identity. */
    NOT_FOR_ME,
    /** Recomputed AAD does not match. */
    AAD_MISMATCH,
    /** CEK unwrap failed. */
    KEY_UNWRAP_FAILED,
    /** GCM authentication failed (including tag verification failure). */
    GCM_AUTH_FAILED,
    /** Inner/outer binding validation failed. */
    BINDING_FAILED,
    /** Signature validation failed. */
    SIGNATURE_INVALID,
    /** Field is missing, conflicting, or has an invalid value. */
    INVALID_FIELD,
    /** Other uncategorized internal errors. */
    INTERNAL_ERROR
}
