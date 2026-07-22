package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WindLetterArmorTest {

    @Test
    void binaryAndBase64UrlRoundTripExactUtf8Bytes() {
        byte[] wire = "{\"payload\":\"风与風\"}".getBytes(StandardCharsets.UTF_8);

        byte[] binary = WindLetterArmor.encodeBinary(wire);
        String text = WindLetterArmor.encodeBase64Url(wire);

        assertArrayEquals(wire, WindLetterArmor.decodeBinary(binary));
        assertArrayEquals(wire, WindLetterArmor.decodeBase64Url(text));
    }
}
