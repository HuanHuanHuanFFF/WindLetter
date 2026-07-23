package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
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
    private static final String VERSION_HASH =
        "f5a2c5ec43b6aede7ec93351b16653e93236df55bf15dd4d14c9b5c9c85707ba";
    private static final String HEADER = "-----風笺 起-----";
    private static final String FOOTER = "-----風笺 凪-----";
    private static final String V1_GUIDE = "渢𩗍𩘥𬱶𬱶凪";

    @Test
    void packagedBodyAlphabetMatchesTheFrozenV1CodePointSequence() throws IOException {
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
        assertFalse(alphabet.contains("凪"));
    }

    @Test
    void versionAlphabetAndV1GuideMatchTheFrozenSequence() {
        String alphabet = WindVersionRadix64.alphabet();

        assertEquals(64, alphabet.codePointCount(0, alphabet.length()));
        assertEquals(64, alphabet.codePoints().distinct().count());
        assertEquals(VERSION_HASH, sha256(alphabet.getBytes(StandardCharsets.UTF_8)));
        assertFalse(alphabet.contains("凪"));
        assertEquals("𬱶", WindVersionRadix64.encodeVersion(BigInteger.ONE));
        assertEquals("渢𩗍𩘥𬱶", WindVersionRadix64.MAGIC_GUIDE);
        assertEquals("𬱶𩘫", WindVersionRadix64.encodeVersion(BigInteger.valueOf(64)));
        String future = WindVersionRadix64.MAGIC_GUIDE + "𬱶𩘫凪body";
        WindVersionRadix64.ParsedGuide parsed = WindVersionRadix64.parseGuide(future);
        assertEquals(BigInteger.valueOf(64), parsed.version());
        assertEquals("body", future.substring(parsed.bodyOffset()));
    }

    @Test
    void emptyJsonUsesTheFrozenWindEnvelopeAndV1Guide() {
        String encoded = WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8));
        String content = content(encoded);

        assertTrue(encoded.startsWith(HEADER + "\n" + V1_GUIDE));
        assertTrue(encoded.endsWith("\n" + FOOTER));
        assertEquals(14, content.codePointCount(0, content.length()));
        assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8), WindLetterArmor.decodeWindBase1024F(encoded));
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
    void rejectsUnknownBodyCodePointsAndUnpairedSurrogates() {
        String valid = WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8));
        String content = content(valid);
        int bodyStart = V1_GUIDE.length();
        int firstEnd = content.offsetByCodePoints(bodyStart, 1);
        String unknownFirst = envelope(content.substring(0, bodyStart) + "A" + content.substring(firstEnd));
        String unpaired = envelope(content + "\ud800");

        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(unknownFirst));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(unpaired));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeWindBase1024F(null));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeWindBase1024F(""));
    }

    @Test
    void rejectsTruncatedExtendedAndNonZeroTailPadding() throws IOException {
        String validContent = content(WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8)));
        int lastStart = validContent.offsetByCodePoints(
            0,
            validContent.codePointCount(0, validContent.length()) - 1
        );
        String truncated = envelope(validContent.substring(0, lastStart));
        int firstSymbol = alphabetCodePoints()[0];
        String extended = envelope(validContent + new String(Character.toChars(firstSymbol)));

        assertReason(ArmorException.Reason.INVALID_LENGTH, () -> WindLetterArmor.decodeWindBase1024F(truncated));
        assertReason(ArmorException.Reason.INVALID_LENGTH, () -> WindLetterArmor.decodeWindBase1024F(extended));

        String paddedContent = content(WindLetterArmor.encodeWindBase1024F("x".getBytes(StandardCharsets.UTF_8)));
        int[] alphabet = alphabetCodePoints();
        String prefix = paddedContent.substring(0, V1_GUIDE.length());
        int[] symbols = paddedContent.substring(V1_GUIDE.length()).codePoints().toArray();
        int lastIndex = indexOf(alphabet, symbols[symbols.length - 1]);
        symbols[symbols.length - 1] = alphabet[lastIndex + 1];
        String nonZeroPadding = envelope(prefix + new String(symbols, 0, symbols.length));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(nonZeroPadding));
    }

    @Test
    void bodyLengthAndChecksumErrorsSurviveWindBasePacking() {
        byte[] frame = WindLetterArmor.encodeBinary("{}".getBytes(StandardCharsets.UTF_8));
        byte[] body = Arrays.copyOfRange(frame, 4, frame.length);

        byte[] badLength = body.clone();
        badLength[3] = 3;
        assertReason(
            ArmorException.Reason.INVALID_LENGTH,
            () -> WindLetterArmor.decodeWindBase1024F(envelope(V1_GUIDE + WindBase1024FCodec.encodeBody(badLength)))
        );

        byte[] badChecksum = body.clone();
        badChecksum[4] ^= 1;
        assertReason(
            ArmorException.Reason.CHECKSUM_MISMATCH,
            () -> WindLetterArmor.decodeWindBase1024F(envelope(V1_GUIDE + WindBase1024FCodec.encodeBody(badChecksum)))
        );
    }

    @Test
    void rejectsInvalidMagicMissingTerminatorAndZeroVersion() {
        String validContent = content(WindLetterArmor.encodeWindBase1024F("{}".getBytes(StandardCharsets.UTF_8)));
        int firstEnd = validContent.offsetByCodePoints(0, 1);
        String badMagic = envelope("𬱶" + validContent.substring(firstEnd));
        String missingTerminator = envelope(validContent.replace("凪", ""));
        String zeroVersion = envelope("渢𩗍𩘥𬱶𩘫凪" + validContent.substring(V1_GUIDE.length()));

        assertReason(ArmorException.Reason.INVALID_MAGIC, () -> WindLetterArmor.decodeWindBase1024F(badMagic));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(missingTerminator));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeWindBase1024F(zeroVersion));
    }

    private int[] alphabetCodePoints() throws IOException {
        try (InputStream input = getClass().getResourceAsStream(RESOURCE)) {
            assertNotNull(input);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).codePoints().toArray();
        }
    }

    private static String content(String armor) {
        int firstNewline = armor.indexOf('\n');
        int lastNewline = armor.lastIndexOf('\n');
        return armor.substring(firstNewline + 1, lastNewline).replace("\n", "");
    }

    private static String envelope(String content) {
        return HEADER + "\n" + content + "\n" + FOOTER;
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
