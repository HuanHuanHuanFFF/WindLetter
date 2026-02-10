package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.VerificationPolicy;
import org.junit.jupiter.api.Test;

class DecryptRequestTest {

    @Test
    void shouldRequireWireOrArmor() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new DecryptRequest(
                " ",
                null,
                new RecipientIdentityRef("me", null),
                VerificationPolicy.AUTO_BY_CTY
            )
        );
    }

    @Test
    void shouldDefaultVerificationPolicy() {
        DecryptRequest request = new DecryptRequest(
            "{\"protected\":\"x\"}",
            null,
            new RecipientIdentityRef("me", null),
            null
        );
        assertEquals(VerificationPolicy.AUTO_BY_CTY, request.verificationPolicy());
    }
}
