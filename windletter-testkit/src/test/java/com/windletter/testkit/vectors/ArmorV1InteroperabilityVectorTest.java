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
    private static final String BASE64_PEM = "-----BEGIN WIND LETTER-----\n"
        + "V0xBAQAAAAJ7fSJftUE=\n"
        + "-----END WIND LETTER-----";
    private static final int[] WIND_CONTENT_CODE_POINTS = {
        0x6e22, 0x295cd, 0x29625, 0x2cc76, 0x2cc76, 0x51ea,
        0x2962b, 0x2962b, 0x2962b, 0x3692, 0x34c3, 0x364a, 0x3438, 0x3654
    };

    @Test
    void commonFrameAndTextCodecsMatchFrozenV1Vector() {
        byte[] expectedFrame = HexFormat.of().parseHex(BINARY_HEX);
        String expectedWindContent = new String(
            WIND_CONTENT_CODE_POINTS,
            0,
            WIND_CONTENT_CODE_POINTS.length
        );
        String expectedWind = "-----風笺 起-----\n"
            + expectedWindContent + "\n"
            + "-----風笺 凪-----";

        assertArrayEquals(expectedFrame, WindLetterArmor.encodeBinary(EMPTY_OBJECT));
        assertEquals(BASE64_PEM, WindLetterArmor.encodeBase64Pem(EMPTY_OBJECT));
        assertEquals(expectedWind, WindLetterArmor.encodeWindBase1024F(EMPTY_OBJECT));
        assertEquals(14, expectedWindContent.codePointCount(0, expectedWindContent.length()));
        assertEquals(21, expectedWindContent.length());

        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeBinary(expectedFrame));
        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeBase64Pem(BASE64_PEM));
        assertArrayEquals(EMPTY_OBJECT, WindLetterArmor.decodeWindBase1024F(expectedWind));
    }
}
