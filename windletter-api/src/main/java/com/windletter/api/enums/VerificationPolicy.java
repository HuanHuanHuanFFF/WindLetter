package com.windletter.api.enums;

/**
 * Receiver-side signature verification policy.
 */
public enum VerificationPolicy {
    /** Decide whether to verify signature automatically by message cty. */
    AUTO_BY_CTY,
    /** Require signature and it must verify successfully. */
    REQUIRE_SIGNED_VALID,
    /** Allow unsigned messages. */
    ALLOW_UNSIGNED
}
