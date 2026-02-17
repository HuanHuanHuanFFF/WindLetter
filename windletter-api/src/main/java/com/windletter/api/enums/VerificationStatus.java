package com.windletter.api.enums;

/**
 * Signature verification result status.
 */
public enum VerificationStatus {
    /** Signed and verified successfully. */
    SIGNED_VALID,
    /** Explicitly an unsigned message. */
    UNSIGNED,
    /** Signature verification is not applicable in the current flow. */
    NOT_APPLICABLE,
    /** Signature verification failed. */
    FAILED
}
