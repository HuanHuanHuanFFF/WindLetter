package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.ArmorFormat;
import org.junit.jupiter.api.Test;

class EncryptedMessageTest {

    @Test
    void shouldRejectBlankWireJson() {
        assertThrows(IllegalArgumentException.class, () -> new EncryptedMessage("   ", null, null, null));
    }

    @Test
    void shouldRejectNonNoneFormatWhenArmorMissing() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptedMessage("{\"k\":\"v\"}", null, null, ArmorFormat.BASE64_PEM)
        );
    }

    @Test
    void shouldRejectNoneFormatWhenArmorPresent() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptedMessage("{\"k\":\"v\"}", "armor-text", null, ArmorFormat.NONE)
        );
    }

    @Test
    void shouldAllowBinaryFormatWithArmorBytes() {
        new EncryptedMessage("{\"k\":\"v\"}", null, new byte[] {1, 2, 3}, ArmorFormat.BINARY);
    }

    @Test
    void shouldRejectBinaryFormatWithArmorStringOrMissingBytes() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptedMessage("{\"k\":\"v\"}", "armor-text", null, ArmorFormat.BINARY)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptedMessage("{\"k\":\"v\"}", null, null, ArmorFormat.BINARY)
        );
    }

    @Test
    void shouldUseDefensiveCopyForArmorBytes() {
        byte[] source = new byte[] {7, 8, 9};
        EncryptedMessage message = new EncryptedMessage("{\"k\":\"v\"}", null, source, ArmorFormat.BINARY);
        source[0] = 0;
        byte[] fromMessage = message.armorBytes();

        assertArrayEquals(new byte[] {7, 8, 9}, fromMessage);
        assertNotSame(fromMessage, message.armorBytes());
    }
}
