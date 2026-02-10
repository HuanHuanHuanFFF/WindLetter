package com.windletter.core.error;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class ErrorCodeTest {

    @Test
    void shouldMatchV1ContractOrderAndNames() {
        String[] expected = {
            "MALFORMED_WIRE",
            "UNSUPPORTED_VERSION",
            "UNSUPPORTED_ALGORITHM",
            "NOT_FOR_ME",
            "AAD_MISMATCH",
            "KEY_UNWRAP_FAILED",
            "GCM_AUTH_FAILED",
            "BINDING_FAILED",
            "SIGNATURE_INVALID",
            "INVALID_FIELD",
            "INTERNAL_ERROR"
        };

        ErrorCode[] values = ErrorCode.values();
        String[] actual = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            actual[i] = values[i].name();
        }
        assertArrayEquals(expected, actual);
    }
}
