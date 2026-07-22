package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class WindBase1024FStrictTest {

    private static final String RESOURCE = "/com/windletter/armor/wind-base-1024f-v1-alphabet.txt";
    private static final String HASH =
        "255519fb0d061d88fbd9a8d216ceb6494e09e9fb72e80d7c1815ca4aef794eba";

    @Test
    void packagedAlphabetMatchesTheFrozenV1CodePointSequence() throws IOException {
        byte[] bytes;
        try (InputStream input = getClass().getResourceAsStream(RESOURCE)) {
            assertNotNull(input);
            bytes = input.readAllBytes();
        }
        String alphabet = new String(bytes, StandardCharsets.UTF_8);

        assertEquals(3339, bytes.length);
        assertEquals(HASH, sha256(bytes));
        assertEquals(1024, alphabet.codePointCount(0, alphabet.length()));
        assertEquals(1291, alphabet.length());
        assertEquals(1024, alphabet.codePoints().distinct().count());
        assertFalse(alphabet.contains("\r"));
        assertFalse(alphabet.contains("\n"));
    }

    @Test
    void emptyJsonHasStableWindBase1024FVector() {
        String expected = new String(
            new int[] {
                0x295ab, 0x35a0, 0x2c1da, 0x449b, 0x2962b, 0x2962b,
                0x29603, 0x29648, 0x98b8, 0x2ea2b, 0x3488, 0x449b
            },
            0,
            12
        );

        assertEquals(expected, WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(12, expected.codePointCount(0, expected.length()));
        assertEquals(19, expected.length());
        assertArrayEquals(
            "{}".getBytes(StandardCharsets.UTF_8),
            WindLetterArmor.decodeWindBase1024F(expected)
        );
    }

    @Test
    void roundTripsAllTenBitTailShapes() {
        for (int length = 1; length <= 15; length++) {
            byte[] value = "x".repeat(length).getBytes(StandardCharsets.UTF_8);
            String encoded = WindLetterArmor.encodeWindBase1024F(value);
            assertArrayEquals(value, WindLetterArmor.decodeWindBase1024F(encoded));
        }
    }

    @Test
    void rejectsUnknownCodePointsAndUnpairedSurrogatesBeforeFrameParsing() {
        String valid = WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8));
        int firstEnd = valid.offsetByCodePoints(0, 1);
        String unknownFirst = "A" + valid.substring(firstEnd);

        assertReason(
            ArmorException.Reason.INVALID_TEXT,
            () -> WindLetterArmor.decodeWindBase1024F(unknownFirst)
        );
        assertReason(
            ArmorException.Reason.INVALID_TEXT,
            () -> WindLetterArmor.decodeWindBase1024F(valid + "\ud800")
        );
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeWindBase1024F(null));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeWindBase1024F(""));
    }

    @Test
    void rejectsTruncatedExtendedAndNonZeroTailPadding() throws IOException {
        String valid = WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8));
        int lastStart = valid.offsetByCodePoints(0, valid.codePointCount(0, valid.length()) - 1);
        String truncated = valid.substring(0, lastStart);
        int firstSymbol = alphabetCodePoints()[0];
        String extended = valid + new String(Character.toChars(firstSymbol));

        assertReason(
            ArmorException.Reason.INVALID_LENGTH,
            () -> WindLetterArmor.decodeWindBase1024F(truncated)
        );
        assertReason(
            ArmorException.Reason.INVALID_LENGTH,
            () -> WindLetterArmor.decodeWindBase1024F(extended)
        );

        int[] alphabet = alphabetCodePoints();
        int[] symbols = valid.codePoints().toArray();
        int lastIndex = indexOf(alphabet, symbols[symbols.length - 1]);
        symbols[symbols.length - 1] = alphabet[lastIndex + 1];
        String nonZeroPadding = new String(symbols, 0, symbols.length);
        assertReason(
            ArmorException.Reason.INVALID_TEXT,
            () -> WindLetterArmor.decodeWindBase1024F(nonZeroPadding)
        );
    }

    @Test
    void commonFrameErrorsSurviveWindBasePacking() {
        byte[] valid = WindLetterArmor.encodeBinary("{}".getBytes(StandardCharsets.UTF_8));

        byte[] badMagic = valid.clone();
        badMagic[0] ^= 1;
        assertReason(
            ArmorException.Reason.INVALID_MAGIC,
            () -> WindLetterArmor.decodeWindBase1024F(WindBase1024FCodec.encodeFrame(badMagic))
        );

        byte[] badVersion = valid.clone();
        badVersion[3] = 2;
        assertReason(
            ArmorException.Reason.UNSUPPORTED_VERSION,
            () -> WindLetterArmor.decodeWindBase1024F(WindBase1024FCodec.encodeFrame(badVersion))
        );

        byte[] badChecksum = valid.clone();
        badChecksum[8] ^= 1;
        assertReason(
            ArmorException.Reason.CHECKSUM_MISMATCH,
            () -> WindLetterArmor.decodeWindBase1024F(WindBase1024FCodec.encodeFrame(badChecksum))
        );
    }

    private int[] alphabetCodePoints() throws IOException {
        try (InputStream input = getClass().getResourceAsStream(RESOURCE)) {
            assertNotNull(input);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).codePoints().toArray();
        }
    }

    private static int indexOf(int[] values, int expected) {
        for (int index = 0; index < values.length; index++) {
            if (values[index] == expected) {
                return index;
            }
        }
        throw new AssertionError("code point is absent from the frozen alphabet");
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void assertReason(ArmorException.Reason expected, Executable executable) {
        ArmorException failure = assertThrows(ArmorException.class, executable);
        assertEquals(expected, failure.reason());
    }
}
