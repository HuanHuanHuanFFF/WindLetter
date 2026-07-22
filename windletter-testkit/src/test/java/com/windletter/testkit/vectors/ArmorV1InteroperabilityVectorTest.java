package com.windletter.testkit.vectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.windletter.armor.WindLetterArmor;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class ArmorV1InteroperabilityVectorTest {

    private static final byte[] EMPTY_OBJECT = "{}".getBytes(StandardCharsets.UTF_8);
    private static final String BINARY_HEX = "574c4101000000027b7d225fb541";
    private static final String BASE64URL = "V0xBAQAAAAJ7fSJftUE";
    private static final int[] WIND_CODE_POINTS = {
        0x295ab, 0x35a0, 0x2c1da, 0x449b, 0x2962b, 0x2962b,
        0x29603, 0x29648, 0x98b8, 0x2ea2b, 0x3488, 0x449b
    };

    @Test
    void commonFrameAndTextCodecsMatchFrozenV1Vector() {
        byte[] expectedFrame = HexFormat.of().parseHex(BINARY_HEX);
        String expectedWind = new String(WIND_CODE_POINTS, 0, WIND_CODE_POINTS.length);

        assertArrayEquals(expectedFrame, WindLetterArmor.encodeBinary(EMPTY_OBJECT));
        assertEquals(BASE64URL, WindLetterArmor.encodeBase64Url(EMPTY_OBJECT));
        assertEquals(expectedWind, WindLetterArmor.encodeWindBase1024F(EMPTY_OBJECT));
        assertEquals(12, expectedWind.codePointCount(0, expectedWind.length()));
        assertEquals(19, expectedWind.length());

        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeBinary(expectedFrame));
        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeBase64Url(BASE64URL));
        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeWindBase1024F(expectedWind));
    }
}
