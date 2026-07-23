package com.windletter.armor;

import com.windletter.protocol.ProtocolLimits;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/** Package-private 10-bit codec for the frozen WIND_BASE_1024F_V1 body alphabet. */
final class WindBase1024FCodec {

    private static final String ALPHABET_RESOURCE =
        "/com/windletter/armor/wind-base-1024f-v1-alphabet.txt";
    private static final String ALPHABET_SHA256 =
        "255519fb0d061d88fbd9a8d216ceb6494e09e9fb72e80d7c1815ca4aef794eba";
    private static final int ALPHABET_SIZE = 1024;
    private static final int BITS_PER_SYMBOL = 10;
    private static final int BODY_OVERHEAD = 8;
    private static final int MAX_BODY_BYTES = ProtocolLimits.MAX_WIRE_UTF8_BYTES + BODY_OVERHEAD;
    private static final int MAX_SYMBOLS = (MAX_BODY_BYTES * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL;
    private static final Alphabet ALPHABET = loadAlphabet();

    private WindBase1024FCodec() {
    }

    static String encodeBody(byte[] body) {
        int symbolCount = (body.length * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL;
        StringBuilder encoded = new StringBuilder(symbolCount * 2);
        int buffer = 0;
        int bitCount = 0;
        for (byte current : body) {
            buffer = buffer << 8 | current & 0xff;
            bitCount += 8;
            while (bitCount >= BITS_PER_SYMBOL) {
                bitCount -= BITS_PER_SYMBOL;
                int value = buffer >>> bitCount & 0x3ff;
                encoded.appendCodePoint(ALPHABET.symbols()[value]);
                buffer &= lowBitMask(bitCount);
            }
        }
        if (bitCount > 0) {
            int value = buffer << (BITS_PER_SYMBOL - bitCount) & 0x3ff;
            encoded.appendCodePoint(ALPHABET.symbols()[value]);
        }
        return encoded.toString();
    }

    static byte[] decodeBody(String armor) {
        int symbolCount = validateAndCountSymbols(armor);
        int packedByteCount = symbolCount * BITS_PER_SYMBOL / 8;
        byte[] packed = new byte[packedByteCount];
        int buffer = 0;
        int bitCount = 0;
        int outputOffset = 0;

        for (int offset = 0; offset < armor.length(); ) {
            int codePoint = armor.codePointAt(offset);
            offset += Character.charCount(codePoint);
            int value = ALPHABET.indexByCodePoint().get(codePoint);
            buffer = buffer << BITS_PER_SYMBOL | value;
            bitCount += BITS_PER_SYMBOL;
            while (bitCount >= 8) {
                bitCount -= 8;
                packed[outputOffset++] = (byte) (buffer >>> bitCount);
                buffer &= lowBitMask(bitCount);
            }
        }

        if (packed.length < BODY_OVERHEAD) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "WindBase1024F body is shorter than the v1 body");
        }

        long payloadLength = readUnsignedInt(packed, 0);
        if (payloadLength == 0 || payloadLength > ProtocolLimits.MAX_WIRE_UTF8_BYTES) {
            throw malformed(ArmorException.Reason.INVALID_LENGTH, "armor payload length is outside the allowed range");
        }
        long expectedBodyBytes = BODY_OVERHEAD + payloadLength;
        long expectedSymbols = (expectedBodyBytes * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL;
        if (expectedSymbols != symbolCount || expectedBodyBytes > packed.length) {
            throw malformed(
                ArmorException.Reason.INVALID_LENGTH,
                "WindBase1024F symbol count does not match the body length"
            );
        }

        for (int i = (int) expectedBodyBytes; i < packed.length; i++) {
            if (packed[i] != 0) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "WindBase1024F trailing padding bits must be zero");
            }
        }
        if (buffer != 0) {
            throw malformed(ArmorException.Reason.INVALID_TEXT, "WindBase1024F trailing padding bits must be zero");
        }
        return Arrays.copyOf(packed, (int) expectedBodyBytes);
    }

    private static int validateAndCountSymbols(String armor) {
        if (armor == null || armor.isEmpty()) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "WindBase1024F body must be non-empty");
        }
        if (armor.length() > MAX_SYMBOLS * 2) {
            throw malformed(ArmorException.Reason.INVALID_INPUT, "WindBase1024F body exceeds the maximum encoded size");
        }

        int symbolCount = 0;
        for (int offset = 0; offset < armor.length(); ) {
            char current = armor.charAt(offset);
            if (Character.isHighSurrogate(current)) {
                if (offset + 1 >= armor.length() || !Character.isLowSurrogate(armor.charAt(offset + 1))) {
                    throw malformed(ArmorException.Reason.INVALID_TEXT, "WindBase1024F contains an unpaired high surrogate");
                }
            } else if (Character.isLowSurrogate(current)) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "WindBase1024F contains an unpaired low surrogate");
            }

            int codePoint = armor.codePointAt(offset);
            if (!ALPHABET.indexByCodePoint().containsKey(codePoint)) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "WindBase1024F contains a code point outside the v1 alphabet");
            }
            offset += Character.charCount(codePoint);
            symbolCount++;
            if (symbolCount > MAX_SYMBOLS) {
                throw malformed(ArmorException.Reason.INVALID_INPUT, "WindBase1024F body exceeds the maximum encoded size");
            }
        }
        return symbolCount;
    }

    private static Alphabet loadAlphabet() {
        byte[] bytes;
        try (InputStream input = WindBase1024FCodec.class.getResourceAsStream(ALPHABET_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("WIND_BASE_1024F_V1 alphabet resource is missing");
            }
            bytes = input.readAllBytes();
        } catch (IOException failure) {
            throw new IllegalStateException("failed to read WIND_BASE_1024F_V1 alphabet resource", failure);
        }

        String actualHash = sha256(bytes);
        if (!ALPHABET_SHA256.equals(actualHash)) {
            throw new IllegalStateException("WIND_BASE_1024F_V1 alphabet resource hash does not match v1");
        }

        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
        } catch (CharacterCodingException failure) {
            throw new IllegalStateException("WIND_BASE_1024F_V1 alphabet resource is not strict UTF-8", failure);
        }

        int[] symbols = text.codePoints().toArray();
        if (symbols.length != ALPHABET_SIZE) {
            throw new IllegalStateException("WIND_BASE_1024F_V1 alphabet must contain 1024 code points");
        }
        Set<Integer> unique = new HashSet<>(ALPHABET_SIZE);
        Map<Integer, Integer> indexes = new HashMap<>(ALPHABET_SIZE * 2);
        for (int index = 0; index < symbols.length; index++) {
            if (!unique.add(symbols[index])) {
                throw new IllegalStateException("WIND_BASE_1024F_V1 alphabet contains duplicate code points");
            }
            indexes.put(symbols[index], index);
        }
        return new Alphabet(symbols, Map.copyOf(indexes));
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static int lowBitMask(int bitCount) {
        return bitCount == 0 ? 0 : (1 << bitCount) - 1;
    }

    private static long readUnsignedInt(byte[] value, int offset) {
        return (long) (value[offset] & 0xff) << 24
            | (long) (value[offset + 1] & 0xff) << 16
            | (long) (value[offset + 2] & 0xff) << 8
            | value[offset + 3] & 0xffL;
    }

    private static ArmorException malformed(ArmorException.Reason reason, String message) {
        return new ArmorException(reason, message);
    }

    private record Alphabet(int[] symbols, Map<Integer, Integer> indexByCodePoint) {
    }
}
