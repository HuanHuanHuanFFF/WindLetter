package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.ArmorFormat;
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
                null,
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
            null,
            null,
            new RecipientIdentityRef("me", null),
            null
        );
        assertEquals(VerificationPolicy.AUTO_BY_CTY, request.verificationPolicy());
        assertEquals(ArmorFormat.NONE, request.armorFormat());
    }

    @Test
    void shouldRejectNoneFormatWhenArmorPresent() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new DecryptRequest(
                null,
                "abc",
                null,
                ArmorFormat.NONE,
                new RecipientIdentityRef("me", null),
                VerificationPolicy.AUTO_BY_CTY
            )
        );
    }

    @Test
    void shouldRejectMultipleInputRepresentations() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new DecryptRequest(
                "{\"protected\":\"x\"}",
                null,
                new byte[] {1, 2},
                ArmorFormat.BINARY,
                new RecipientIdentityRef("me", null),
                VerificationPolicy.AUTO_BY_CTY
            )
        );
    }

    @Test
    void shouldInferBinaryFormatWhenArmorBytesProvided() {
        DecryptRequest request = new DecryptRequest(
            null,
            null,
            new byte[] {3, 4},
            null,
            new RecipientIdentityRef("me", null),
            VerificationPolicy.AUTO_BY_CTY
        );
        assertEquals(ArmorFormat.BINARY, request.armorFormat());
    }

    @Test
    void shouldUseDefensiveCopyForArmorBytes() {
        byte[] source = new byte[] {10, 20};
        DecryptRequest request = new DecryptRequest(
            null,
            null,
            source,
            ArmorFormat.BINARY,
            new RecipientIdentityRef("me", null),
            VerificationPolicy.AUTO_BY_CTY
        );
        source[0] = 0;
        byte[] actual = request.armorBytes();
        assertArrayEquals(new byte[] {10, 20}, actual);
        assertNotSame(actual, request.armorBytes());
    }
}
