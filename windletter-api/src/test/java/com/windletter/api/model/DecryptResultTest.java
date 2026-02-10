package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.core.error.ErrorCode;
import org.junit.jupiter.api.Test;

class DecryptResultTest {

    @Test
    void shouldRequirePayloadWhenSuccess() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new DecryptResult(
                DecryptStatus.SUCCESS,
                null,
                null,
                VerificationStatus.UNSIGNED,
                null,
                null,
                null
            )
        );
    }

    @Test
    void shouldRejectPayloadForNonSuccess() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new DecryptResult(
                DecryptStatus.INVALID_MESSAGE,
                new Payload("text/plain", new byte[] {1}, 1),
                null,
                VerificationStatus.FAILED,
                ErrorCode.INVALID_FIELD,
                null,
                null
            )
        );
    }
}
