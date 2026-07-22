package com.windletter.armor;

import com.windletter.protocol.ProtocolLimits;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.CRC32;

/** WindLetter project armor v1 binary and Base64URL codecs. */
public final class WindLetterArmor {

    private static final byte[] MAGIC = {'W', 'L', 'A'};
    private static final int VERSION = 1;
    private static final int HEADER_BYTES = 8;
    private static final int CHECKSUM_BYTES = 4;
    private static final int FRAME_OVERHEAD = HEADER_BYTES + CHECKSUM_BYTES;
    private static final int MAX_FRAME_BYTES = ProtocolLimits.MAX_WIRE_UTF8_BYTES + FRAME_OVERHEAD;
    private static final int MAX_BASE64URL_CHARS = (MAX_FRAME_BYTES * 4 + 2) / 3;
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

    private WindLetterArmor() {
    }

    /** Frames exact strict UTF-8 outer JSON bytes for binary transport. */
    public static byte[] encodeBinary(byte[] wireJsonUtf8) {
        validateWireForEncoding(wireJsonUtf8);

        byte[] frame = new byte[wireJsonUtf8.length + FRAME_OVERHEAD];
        System.arraycopy(MAGIC, 0, frame, 0, MAGIC.length);
        frame[3] = VERSION;
        writeUnsignedInt(frame, 4, wireJsonUtf8.length);
        System.arraycopy(wireJsonUtf8, 0, frame, HEADER_BYTES, wireJsonUtf8.length);
        writeUnsignedInt(frame, HEADER_BYTES + wireJsonUtf8.length, checksum(frame, 0, HEADER_BYTES + wireJsonUtf8.length));
        return frame;
    }

    /** Decodes and validates a complete binary armor v1 frame. */
    public static byte[] decodeBinary(byte[] armor) {
        if (armor == null || armor.length == 0) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "binary armor must be non-empty");
        }
        if (armor.length > MAX_FRAME_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "binary armor exceeds the maximum encoded size");
        }
        if (armor.length < FRAME_OVERHEAD) {
            throw malformed(ArmorException.Reason.INVALID_MAGIC, "binary armor is shorter than the v1 frame");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (armor[i] != MAGIC[i]) {
                throw malformed(ArmorException.Reason.INVALID_MAGIC, "binary armor magic is invalid");
            }
        }
        int version = armor[3] & 0xff;
        if (version != VERSION) {
            throw malformed(ArmorException.Reason.UNSUPPORTED_VERSION, "unsupported armor frame version: " + version);
        }

        long payloadLength = readUnsignedInt(armor, 4);
        if (payloadLength == 0 || payloadLength > ProtocolLimits.MAX_WIRE_UTF8_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "armor payload length is outside the allowed range");
        }
        long expectedFrameLength = FRAME_OVERHEAD + payloadLength;
        if (expectedFrameLength != armor.length) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "armor payload length does not match the frame size");
        }

        int checksumOffset = HEADER_BYTES + (int) payloadLength;
        long expectedChecksum = readUnsignedInt(armor, checksumOffset);
        long actualChecksum = checksum(armor, 0, checksumOffset);
        if (expectedChecksum != actualChecksum) {
            throw malformed(ArmorException.Reason.CHECKSUM_MISMATCH, "armor CRC-32 does not match");
        }

        byte[] wireJsonUtf8 = Arrays.copyOfRange(armor, HEADER_BYTES, checksumOffset);
        validateDecodedUtf8(wireJsonUtf8);
        return wireJsonUtf8;
    }

    /** Encodes the common binary frame as canonical unpadded Base64URL text. */
    public static String encodeBase64Url(byte[] wireJsonUtf8) {
        return BASE64URL_ENCODER.encodeToString(encodeBinary(wireJsonUtf8));
    }

    /** Decodes canonical unpadded Base64URL text and validates the common frame. */
    public static byte[] decodeBase64Url(String armor) {
        if (armor == null || armor.isEmpty()) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "Base64URL armor must be non-empty");
        }
        if (armor.length() > MAX_BASE64URL_CHARS) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "Base64URL armor exceeds the maximum encoded size");
        }
        for (int i = 0; i < armor.length(); i++) {
            char current = armor.charAt(i);
            boolean allowed = current >= 'A' && current <= 'Z'
                || current >= 'a' && current <= 'z'
                || current >= '0' && current <= '9'
                || current == '-'
                || current == '_';
            if (!allowed) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64URL armor is not canonical unpadded text");
            }
        }

        byte[] frame;
        try {
            frame = BASE64URL_DECODER.decode(armor);
        } catch (IllegalArgumentException failure) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64URL armor is invalid", failure);
        }
        if (!BASE64URL_ENCODER.encodeToString(frame).equals(armor)) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64URL armor is not canonical");
        }
        return decodeBinary(frame);
    }

    private static void validateWireForEncoding(byte[] wireJsonUtf8) {
        if (wireJsonUtf8 == null || wireJsonUtf8.length == 0) {
            throw new IllegalArgumentException("wireJsonUtf8 must be non-empty");
        }
        if (wireJsonUtf8.length > ProtocolLimits.MAX_WIRE_UTF8_BYTES) {
            throw new IllegalArgumentException("wireJsonUtf8 exceeds the maximum wire size");
        }
        try {
            strictUtf8Decoder().decode(ByteBuffer.wrap(wireJsonUtf8));
        } catch (CharacterCodingException failure) {
            throw new IllegalArgumentException("wireJsonUtf8 must contain strict UTF-8", failure);
        }
    }

    private static void validateDecodedUtf8(byte[] value) {
        try {
            strictUtf8Decoder().decode(ByteBuffer.wrap(value));
        } catch (CharacterCodingException failure) {
            throw malformed(ArmorException.Reason.INVALID_UTF8, "armor payload is not strict UTF-8", failure);
        }
    }

    private static java.nio.charset.CharsetDecoder strictUtf8Decoder() {
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
    }

    private static long checksum(byte[] value, int offset, int length) {
        CRC32 crc32 = new CRC32();
        crc32.update(value, offset, length);
        return crc32.getValue();
    }

    private static long readUnsignedInt(byte[] value, int offset) {
        return (long) (value[offset] & 0xff) << 24
            | (long) (value[offset + 1] & 0xff) << 16
            | (long) (value[offset + 2] & 0xff) << 8
            | value[offset + 3] & 0xffL;
    }

    private static void writeUnsignedInt(byte[] target, int offset, long value) {
        target[offset] = (byte) (value >>> 24);
        target[offset + 1] = (byte) (value >>> 16);
        target[offset + 2] = (byte) (value >>> 8);
        target[offset + 3] = (byte) value;
    }

    private static ArmorException malformed(ArmorException.Reason reason, String message) {
        return new ArmorException(reason, message);
    }

    private static ArmorException malformed(
        ArmorException.Reason reason,
        String message,
        Throwable cause
    ) {
        return new ArmorException(reason, message, cause);
    }
}
