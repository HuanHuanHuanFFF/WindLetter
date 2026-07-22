package com.windletter.armor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class WindLetterArmorStrictTest {

    @Test
    void emptyJsonHasStableBinaryAndBase64UrlVector() {
        byte[] expectedFrame = HexFormat.of().parseHex("574c4101000000027b7d225fb541");

        assertArrayEquals(expectedFrame, WindLetterArmor.encodeBinary("{}".getBytes(StandardCharsets.UTF_8)));
        assertEquals("V0xBAQAAAAJ7fSJftUE", WindLetterArmor.encodeBase64Url("{}".getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8), WindLetterArmor.decodeBinary(expectedFrame));
        assertArrayEquals(
            "{}".getBytes(StandardCharsets.UTF_8),
            WindLetterArmor.decodeBase64Url("V0xBAQAAAAJ7fSJftUE")
        );
    }

    @Test
    void textArmorIsCanonicalUnpaddedEncodingOfTheBinaryFrame() {
        byte[] wire = "{\"v\":1}".getBytes(StandardCharsets.UTF_8);
        byte[] binary = WindLetterArmor.encodeBinary(wire);

        assertEquals(
            Base64.getUrlEncoder().withoutPadding().encodeToString(binary),
            WindLetterArmor.encodeBase64Url(wire)
        );
    }

    @Test
    void rejectsNonCanonicalOrInvalidBase64UrlBeforeFrameParsing() {
        String canonical = WindLetterArmor.encodeBase64Url("{}".getBytes(StandardCharsets.UTF_8));

        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeBase64Url(canonical + "="));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeBase64Url(canonical + "\n"));
        assertReason(ArmorException.Reason.INVALID_TEXT, () -> WindLetterArmor.decodeBase64Url("*" + canonical));

        String nonCanonicalTailBits = canonical.substring(0, canonical.length() - 1) + "F";
        assertReason(
            ArmorException.Reason.INVALID_TEXT,
            () -> WindLetterArmor.decodeBase64Url(nonCanonicalTailBits)
        );
    }

    @Test
    void binaryFailurePriorityIsMagicThenVersionThenLengthThenChecksum() {
        byte[] valid = WindLetterArmor.encodeBinary("{}".getBytes(StandardCharsets.UTF_8));

        byte[] badMagicAndVersion = valid.clone();
        badMagicAndVersion[0] ^= 1;
        badMagicAndVersion[3] = 2;
        assertReason(ArmorException.Reason.INVALID_MAGIC, () -> WindLetterArmor.decodeBinary(badMagicAndVersion));

        byte[] badVersionAndLength = valid.clone();
        badVersionAndLength[3] = 2;
        badVersionAndLength[7] = 3;
        assertReason(
            ArmorException.Reason.UNSUPPORTED_VERSION,
            () -> WindLetterArmor.decodeBinary(badVersionAndLength)
        );

        byte[] badLengthAndChecksum = valid.clone();
        badLengthAndChecksum[7] = 3;
        badLengthAndChecksum[badLengthAndChecksum.length - 1] ^= 1;
        assertReason(ArmorException.Reason.INVALID_LENGTH, () -> WindLetterArmor.decodeBinary(badLengthAndChecksum));

        byte[] badChecksum = valid.clone();
        badChecksum[8] ^= 1;
        assertReason(ArmorException.Reason.CHECKSUM_MISMATCH, () -> WindLetterArmor.decodeBinary(badChecksum));
    }

    @Test
    void rejectsTruncatedExtendedAndZeroLengthFrames() {
        byte[] valid = WindLetterArmor.encodeBinary("{}".getBytes(StandardCharsets.UTF_8));

        assertReason(
            ArmorException.Reason.INVALID_LENGTH,
            () -> WindLetterArmor.decodeBinary(Arrays.copyOf(valid, valid.length - 1))
        );
        assertReason(
            ArmorException.Reason.INVALID_LENGTH,
            () -> WindLetterArmor.decodeBinary(Arrays.copyOf(valid, valid.length + 1))
        );

        byte[] zeroLength = frameWithPayload(new byte[0]);
        assertReason(ArmorException.Reason.INVALID_LENGTH, () -> WindLetterArmor.decodeBinary(zeroLength));
    }

    @Test
    void rejectsPayloadThatIsNotStrictUtf8AfterChecksumValidation() {
        byte[] invalidUtf8Frame = frameWithPayload(new byte[] {(byte) 0xc3});

        assertReason(ArmorException.Reason.INVALID_UTF8, () -> WindLetterArmor.decodeBinary(invalidUtf8Frame));
        assertThrows(
            IllegalArgumentException.class,
            () -> WindLetterArmor.encodeBinary(new byte[] {(byte) 0xc3})
        );
    }

    @Test
    void rejectsEmptyAndOversizedInputsBeforeAllocationHeavyDecoding() {
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeBinary(null));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeBinary(new byte[0]));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeBase64Url(null));
        assertReason(ArmorException.Reason.INVALID_INPUT, () -> WindLetterArmor.decodeBase64Url(""));

        byte[] oversizedWire = new byte[20 * 1024 * 1024 + 1];
        assertThrows(IllegalArgumentException.class, () -> WindLetterArmor.encodeBinary(oversizedWire));
    }

    private static byte[] frameWithPayload(byte[] payload) {
        byte[] frame = new byte[12 + payload.length];
        frame[0] = 'W';
        frame[1] = 'L';
        frame[2] = 'A';
        frame[3] = 1;
        frame[4] = (byte) (payload.length >>> 24);
        frame[5] = (byte) (payload.length >>> 16);
        frame[6] = (byte) (payload.length >>> 8);
        frame[7] = (byte) payload.length;
        System.arraycopy(payload, 0, frame, 8, payload.length);

        CRC32 crc32 = new CRC32();
        crc32.update(frame, 0, 8 + payload.length);
        long checksum = crc32.getValue();
        int checksumOffset = 8 + payload.length;
        frame[checksumOffset] = (byte) (checksum >>> 24);
        frame[checksumOffset + 1] = (byte) (checksum >>> 16);
        frame[checksumOffset + 2] = (byte) (checksum >>> 8);
        frame[checksumOffset + 3] = (byte) checksum;
        return frame;
    }

    private static void assertReason(ArmorException.Reason expected, Executable executable) {
        ArmorException failure = assertThrows(ArmorException.class, executable);
        assertEquals(expected, failure.reason());
    }
}
