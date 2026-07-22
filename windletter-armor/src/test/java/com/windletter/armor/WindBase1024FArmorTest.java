package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WindBase1024FArmorTest {

    @Test
    void roundTripsExactUtf8BytesByUnicodeCodePoint() {
        byte[] wire = ("{\"payload\":\"" + "wind".repeat(128) + "\"}")
            .getBytes(StandardCharsets.UTF_8);

        String armor = WindLetterArmor.encodeWindBase1024F(wire);

        assertTrue(armor.codePointCount(0, armor.length()) < armor.length());
        assertArrayEquals(wire, WindLetterArmor.decodeWindBase1024F(armor));
    }
}
