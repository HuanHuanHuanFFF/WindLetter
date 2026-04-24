package com.windletter.protocol.wire;

/**
 * Recipient kid fields in public mode.
 */
public record RecipientKid(String x25519, String mlkem768) {

    public RecipientKid {
        x25519 = WireChecks.requireNonBlank(x25519, "x25519");
        if (mlkem768 != null) {
            mlkem768 = WireChecks.requireNonBlank(mlkem768, "mlkem768");
        }
    }
}
