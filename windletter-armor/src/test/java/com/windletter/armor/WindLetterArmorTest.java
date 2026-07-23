package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WindLetterArmorTest {

    @Test
    void binaryAndBase64PemRoundTripExactUtf8Bytes() {
        byte[] wire = "{\"payload\":\"風笺\"}".getBytes(StandardCharsets.UTF_8);

        byte[] binary = WindLetterArmor.encodeBinary(wire);
        String text = WindLetterArmor.encodeBase64Pem(wire);

        assertArrayEquals(wire, WindLetterArmor.decodeBinary(binary));
        assertArrayEquals(wire, WindLetterArmor.decodeBase64Pem(text));
    }
}
