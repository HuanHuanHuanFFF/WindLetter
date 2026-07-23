package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class WindLetterArmorEnvelopeTest {

    private static final String BASE64_HEADER = "-----BEGIN WIND LETTER-----";
    private static final String BASE64_FOOTER = "-----END WIND LETTER-----";
    private static final String WIND_HEADER = "-----風笺 起-----";
    private static final String WIND_FOOTER = "-----風笺 凪-----";
    private static final String WIND_V1_GUIDE = "渢𩗍𩘥𬱶𬱶凪";

    @Test
    void emptyJsonHasStableStandardBase64PemVector() {
        byte[] wire = "{}".getBytes(StandardCharsets.UTF_8);
        String expected = BASE64_HEADER + "\n"
            + "V0xBAQAAAAJ7fSJftUE=" + "\n"
            + BASE64_FOOTER;

        assertEquals(expected, WindLetterArmor.encodeBase64Pem(wire));
        assertArrayEquals(wire, WindLetterArmor.decodeBase64Pem(expected));
        assertArrayEquals(wire, WindLetterArmor.decodeBase64Pem(expected.replace("\n", "\r\n")));
    }

    @Test
    void windTextStartsWithFrozenV1GuideAndWrapsByCodePoint() {
        byte[] wire = ("{\"payload\":\"" + "風".repeat(200) + "\"}")
            .getBytes(StandardCharsets.UTF_8);

        String armor = WindLetterArmor.encodeWindBase1024F(wire);
        String[] lines = armor.split("\n", -1);

        assertEquals(WIND_HEADER, lines[0]);
        assertEquals(WIND_FOOTER, lines[lines.length - 1]);
        assertTrue(lines[1].startsWith(WIND_V1_GUIDE));
        for (int line = 1; line < lines.length - 2; line++) {
            assertEquals(64, lines[line].codePointCount(0, lines[line].length()));
        }
        assertArrayEquals(wire, WindLetterArmor.decodeWindBase1024F(armor));
        assertArrayEquals(wire, WindLetterArmor.decodeWindBase1024F(armor.replace("\n", "\r\n")));
    }

    @Test
    void autoRoutingUsesExactHeaderInsteadOfCharacterHeuristics() {
        byte[] wire = "{}".getBytes(StandardCharsets.UTF_8);
        String base64 = WindLetterArmor.encodeBase64Pem(wire);
        String wind = WindLetterArmor.encodeWindBase1024F(wire);

        assertArrayEquals(wire, WindLetterArmor.decodeTextAuto(base64));
        assertArrayEquals(wire, WindLetterArmor.decodeTextAuto(wind));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeTextAuto("中文但不是風笺头"));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeTextAuto("ASCII but not a PEM header"));
    }

    @Test
    void windVersionIsRejectedBeforeTheBodyAlphabetIsDecoded() {
        String unsupported = WIND_HEADER + "\n"
            + "渢𩗍𩘥𬱶䫻凪A" + "\n"
            + WIND_FOOTER;
        String leadingZero = WIND_HEADER + "\n"
            + "渢𩗍𩘥𬱶𩘫𬱶凪" + "\n"
            + WIND_FOOTER;

        assertReason(ArmorException.Reason.UNSUPPORTED_VERSION, () -> WindLetterArmor.decodeWindBase1024F(unsupported));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(leadingZero));
    }

    private static void assertReason(ArmorException.Reason expected, Executable executable) {
        ArmorException failure = assertThrows(ArmorException.class, executable);
        assertEquals(expected, failure.reason());
    }
}
