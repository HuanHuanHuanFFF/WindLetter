package com.windletter.armor;

import com.windletter.protocol.ProtocolLimits;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.CRC32;

/** WindLetter binary, standard Base64 PEM, and Wind text armor codecs. */
public final class WindLetterArmor {

    private static final byte[] MAGIC = {'W', 'L', 'A'};
    private static final BigInteger VERSION = BigInteger.ONE;
    private static final int LENGTH_BYTES = 4;
    private static final int CHECKSUM_BYTES = 4;
    private static final int MAX_VERSION_VARINT_BYTES = 64;
    private static final int CURRENT_FRAME_OVERHEAD = MAGIC.length + 1 + LENGTH_BYTES + CHECKSUM_BYTES;
    private static final int MAX_FRAME_BYTES = ProtocolLimits.MAX_WIRE_UTF8_BYTES
        + MAGIC.length + MAX_VERSION_VARINT_BYTES + LENGTH_BYTES + CHECKSUM_BYTES;
    private static final String BASE64_HEADER = "-----BEGIN WIND LETTER-----";
    private static final String BASE64_FOOTER = "-----END WIND LETTER-----";
    private static final String WIND_HEADER = "-----風笺 起-----";
    private static final String WIND_FOOTER = "-----風笺 凪-----";
    private static final int TEXT_LINE_CODE_POINTS = 64;
    private static final int MAX_BASE64_BODY_CHARS = ((MAX_FRAME_BYTES + 2) / 3) * 4;
    private static final int MAX_WIND_BODY_SYMBOLS =
        ((ProtocolLimits.MAX_WIRE_UTF8_BYTES + LENGTH_BYTES + CHECKSUM_BYTES) * 8 + 9) / 10;
    private static final int MAX_BASE64_TEXT_CHARS = envelopeLimit(MAX_BASE64_BODY_CHARS, false);
    private static final int MAX_WIND_TEXT_CHARS = envelopeLimit(
        MAX_WIND_BODY_SYMBOLS + WindVersionRadix64.MAGIC_GUIDE.codePointCount(
            0,
            WindVersionRadix64.MAGIC_GUIDE.length()
        ) + 76,
        true
    );
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    private WindLetterArmor() {
    }

    /** Frames exact strict UTF-8 outer JSON bytes for binary transport. */
    public static byte[] encodeBinary(byte[] wireJsonUtf8) {
        validateWireForEncoding(wireJsonUtf8);

        byte[] encodedVersion = encodeUnsignedLeb128(VERSION);
        int payloadOffset = MAGIC.length + encodedVersion.length + LENGTH_BYTES;
        byte[] frame = new byte[wireJsonUtf8.length + CURRENT_FRAME_OVERHEAD];
        System.arraycopy(MAGIC, 0, frame, 0, MAGIC.length);
        System.arraycopy(encodedVersion, 0, frame, MAGIC.length, encodedVersion.length);
        writeUnsignedInt(frame, MAGIC.length + encodedVersion.length, wireJsonUtf8.length);
        System.arraycopy(wireJsonUtf8, 0, frame, payloadOffset, wireJsonUtf8.length);
        int checksumOffset = payloadOffset + wireJsonUtf8.length;
        writeUnsignedInt(frame, checksumOffset, checksum(frame, 0, checksumOffset));
        return frame;
    }

    /** Decodes a complete binary armor frame with a canonical extensible version. */
    public static byte[] decodeBinary(byte[] armor) {
        if (armor == null || armor.length == 0) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "binary armor must be non-empty");
        }
        if (armor.length > MAX_FRAME_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "binary armor exceeds the maximum encoded size");
        }
        if (armor.length < MAGIC.length) {
            throw malformed(ArmorException.Reason.INVALID_MAGIC, "binary armor is shorter than the magic");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (armor[i] != MAGIC[i]) {
                throw malformed(ArmorException.Reason.INVALID_MAGIC, "binary armor magic is invalid");
            }
        }

        ParsedVersion parsedVersion = parseUnsignedLeb128(armor, MAGIC.length);
        if (!VERSION.equals(parsedVersion.value())) {
            throw malformed(
                ArmorException.Reason.UNSUPPORTED_VERSION,
                "unsupported armor frame version: " + parsedVersion.value()
            );
        }
        int lengthOffset = parsedVersion.nextOffset();
        if (armor.length < lengthOffset + LENGTH_BYTES + CHECKSUM_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "binary armor is shorter than the v1 frame");
        }

        long payloadLength = readUnsignedInt(armor, lengthOffset);
        if (payloadLength == 0 || payloadLength > ProtocolLimits.MAX_WIRE_UTF8_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "armor payload length is outside the allowed range");
        }
        long expectedFrameLength = lengthOffset + LENGTH_BYTES + payloadLength + CHECKSUM_BYTES;
        if (expectedFrameLength != armor.length) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "armor payload length does not match the frame size");
        }

        int payloadOffset = lengthOffset + LENGTH_BYTES;
        int checksumOffset = payloadOffset + (int) payloadLength;
        long expectedChecksum = readUnsignedInt(armor, checksumOffset);
        long actualChecksum = checksum(armor, 0, checksumOffset);
        if (expectedChecksum != actualChecksum) {
            throw malformed(ArmorException.Reason.CHECKSUM_MISMATCH, "armor CRC-32 does not match");
        }

        byte[] wireJsonUtf8 = Arrays.copyOfRange(armor, payloadOffset, checksumOffset);
        validateDecodedUtf8(wireJsonUtf8);
        return wireJsonUtf8;
    }

    /** Encodes the common frame as RFC 4648 padded Base64 inside a PEM-style envelope. */
    public static String encodeBase64Pem(byte[] wireJsonUtf8) {
        String body = BASE64_ENCODER.encodeToString(encodeBinary(wireJsonUtf8));
        return wrapEnvelope(BASE64_HEADER, body, BASE64_FOOTER);
    }

    /** Strictly decodes the standard Base64 PEM text and validates the common frame. */
    public static byte[] decodeBase64Pem(String armor) {
        String body = unwrapEnvelope(
            armor,
            BASE64_HEADER,
            BASE64_FOOTER,
            MAX_BASE64_TEXT_CHARS,
            false
        );
        if (body.length() > MAX_BASE64_BODY_CHARS) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "Base64 armor exceeds the maximum encoded size");
        }
        for (int i = 0; i < body.length(); i++) {
            char current = body.charAt(i);
            boolean allowed = current >= 'A' && current <= 'Z'
                || current >= 'a' && current <= 'z'
                || current >= '0' && current <= '9'
                || current == '+'
                || current == '/'
                || current == '=';
            if (!allowed) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64 armor contains a non-standard character");
            }
        }

        byte[] frame;
        try {
            frame = BASE64_DECODER.decode(body);
        } catch (IllegalArgumentException failure) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64 armor is invalid", failure);
        }
        if (!BASE64_ENCODER.encodeToString(frame).equals(body)) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "Base64 armor is not canonical padded text");
        }
        return decodeBinary(frame);
    }

    /** Encodes v1 using the frozen version guide and WindBase1024F body alphabet. */
    public static String encodeWindBase1024F(byte[] wireJsonUtf8) {
        byte[] frame = encodeBinary(wireJsonUtf8);
        int bodyOffset = MAGIC.length + encodeUnsignedLeb128(VERSION).length;
        String content = WindVersionRadix64.MAGIC_GUIDE
            + WindVersionRadix64.encodeVersion(VERSION)
            + new String(Character.toChars(WindVersionRadix64.TERMINATOR))
            + WindBase1024FCodec.encodeBody(Arrays.copyOfRange(frame, bodyOffset, frame.length));
        return wrapEnvelope(WIND_HEADER, content, WIND_FOOTER);
    }

    /** Strictly decodes Wind text after selecting its body alphabet from the version guide. */
    public static byte[] decodeWindBase1024F(String armor) {
        String content = unwrapEnvelope(
            armor,
            WIND_HEADER,
            WIND_FOOTER,
            MAX_WIND_TEXT_CHARS,
            true
        );
        WindVersionRadix64.ParsedGuide guide = WindVersionRadix64.parseGuide(content);
        if (!VERSION.equals(guide.version())) {
            throw malformed(
                ArmorException.Reason.UNSUPPORTED_VERSION,
                "unsupported Wind text version: " + guide.version()
            );
        }

        byte[] body = WindBase1024FCodec.decodeBody(content.substring(guide.bodyOffset()));
        byte[] encodedVersion = encodeUnsignedLeb128(guide.version());
        byte[] frame = new byte[MAGIC.length + encodedVersion.length + body.length];
        System.arraycopy(MAGIC, 0, frame, 0, MAGIC.length);
        System.arraycopy(encodedVersion, 0, frame, MAGIC.length, encodedVersion.length);
        System.arraycopy(body, 0, frame, MAGIC.length + encodedVersion.length, body.length);
        return decodeBinary(frame);
    }

    /** Routes only exact English or Chinese armor headers, then applies the selected strict decoder. */
    public static byte[] decodeTextAuto(String armor) {
        if (armor == null || armor.isEmpty()) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "text armor must be non-empty");
        }
        if (hasExactOpeningLine(armor, BASE64_HEADER)) {
            return decodeBase64Pem(armor);
        }
        if (hasExactOpeningLine(armor, WIND_HEADER)) {
            return decodeWindBase1024F(armor);
        }
        throw malformed(ArmorException.Reason.INVALID_TEXT, "text armor header is not recognized");
    }

    private static byte[] encodeUnsignedLeb128(BigInteger value) {
        if (value == null || value.signum() <= 0) {
            throw new IllegalArgumentException("armor version must be positive");
        }
        byte[] reversed = new byte[MAX_VERSION_VARINT_BYTES];
        BigInteger remaining = value;
        int count = 0;
        while (remaining.signum() > 0) {
            if (count == reversed.length) {
                throw new IllegalArgumentException("armor version exceeds the safe encoding limit");
            }
            reversed[count++] = (byte) remaining.and(BigInteger.valueOf(0x7f)).intValue();
            remaining = remaining.shiftRight(7);
        }
        byte[] encoded = new byte[count];
        for (int i = 0; i < count; i++) {
            encoded[i] = reversed[i];
            if (i + 1 < count) {
                encoded[i] |= (byte) 0x80;
            }
        }
        return encoded;
    }

    private static ParsedVersion parseUnsignedLeb128(byte[] frame, int offset) {
        BigInteger value = BigInteger.ZERO;
        for (int group = 0; group < MAX_VERSION_VARINT_BYTES; group++) {
            if (offset >= frame.length) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "armor version is unterminated");
            }
            int current = frame[offset++] & 0xff;
            int digit = current & 0x7f;
            value = value.or(BigInteger.valueOf(digit).shiftLeft(group * 7));
            if ((current & 0x80) == 0) {
                if (group > 0 && digit == 0) {
                    throw malformed(ArmorException.Reason.INVALID_TEXT, "armor version is not canonical unsigned LEB128");
                }
                if (value.signum() == 0) {
                    throw malformed(ArmorException.Reason.INVALID_TEXT, "armor version must be positive");
                }
                return new ParsedVersion(value, offset);
            }
        }
        throw malformed(ArmorException.Reason.INVALID_INPUT, "armor version exceeds the safe scan limit");
    }

    private static String wrapEnvelope(String header, String content, String footer) {
        StringBuilder wrapped = new StringBuilder(header.length() + content.length() + footer.length() + 8);
        wrapped.append(header).append('\n');
        for (int offset = 0; offset < content.length(); ) {
            int end = offset;
            for (int count = 0; count < TEXT_LINE_CODE_POINTS && end < content.length(); count++) {
                end += Character.charCount(content.codePointAt(end));
            }
            wrapped.append(content, offset, end).append('\n');
            offset = end;
        }
        return wrapped.append(footer).toString();
    }

    private static String unwrapEnvelope(
        String armor,
        String header,
        String footer,
        int maxTextChars,
        boolean codePointLines
    ) {
        if (armor == null || armor.isEmpty()) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "text armor must be non-empty");
        }
        if (armor.length() > maxTextChars) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "text armor exceeds the maximum encoded size");
        }
        for (int index = 0; index < armor.length(); index++) {
            if (armor.charAt(index) == '\r'
                && (index + 1 >= armor.length() || armor.charAt(index + 1) != '\n')) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "text armor contains a bare carriage return");
            }
        }

        String normalized = armor.replace("\r\n", "\n");
        String[] lines = normalized.split("\n", -1);
        if (lines.length < 3 || !header.equals(lines[0]) || !footer.equals(lines[lines.length - 1])) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "text armor envelope is invalid");
        }

        StringBuilder content = new StringBuilder();
        for (int line = 1; line < lines.length - 1; line++) {
            String current = lines[line];
            int width = codePointLines
                ? current.codePointCount(0, current.length())
                : current.length();
            if (width == 0 || width > TEXT_LINE_CODE_POINTS) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "text armor line width is invalid");
            }
            if (line < lines.length - 2 && width != TEXT_LINE_CODE_POINTS) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "text armor contains a short non-final line");
            }
            content.append(current);
        }
        return content.toString();
    }

    private static boolean hasExactOpeningLine(String armor, String header) {
        return armor.startsWith(header + "\n") || armor.startsWith(header + "\r\n");
    }

    private static int envelopeLimit(int bodyCodePoints, boolean mayUseSurrogates) {
        long bodyChars = mayUseSurrogates ? (long) bodyCodePoints * 2 : bodyCodePoints;
        long lineBreakChars = ((long) bodyCodePoints + TEXT_LINE_CODE_POINTS - 1)
            / TEXT_LINE_CODE_POINTS * 2;
        long total = bodyChars + lineBreakChars + 256;
        return total > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) total;
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

    private record ParsedVersion(BigInteger value, int nextOffset) {
    }
}
