package com.windletter.armor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/** Frozen code-point-safe radix-64 codec for the Wind text magic and version. */
final class WindVersionRadix64 {

    static final int TERMINATOR = 0x51ea;
    static final String MAGIC_GUIDE = "渢𩗍𩘥𬱶";

    private static final String ALPHABET =
        "𩘫𬱶䫻飍𩙡䬕𩙢𩙣𬇚䬍𪕴𩗲𦣕䬐𩙍𨅏"
            + "幻風𩗾𩗞䬓渢闏𩘽𩖜颭颴𩗟𩙟𮨨𮨬𦂱"
            + "𢇉𩘩𩗽䬑颳䬚𩙏𩗭𩖪飀𩖣颻䑺𬷣堸𩙓"
            + "𩘼𩘥𩙉𩗙𩗍𮨱𩖾𩖴𩖚𩙠䬛𩙘𮨳𧍯䫹𠑒";
    private static final String ALPHABET_SHA256 =
        "f5a2c5ec43b6aede7ec93351b16653e93236df55bf15dd4d14c9b5c9c85707ba";
    private static final int RADIX = 64;
    private static final int MAX_VERSION_DIGITS = 75;
    private static final int[] SYMBOLS = ALPHABET.codePoints().toArray();
    private static final Map<Integer, Integer> INDEXES = buildIndexes();

    private WindVersionRadix64() {
    }

    static String alphabet() {
        return ALPHABET;
    }

    static String encodeVersion(BigInteger version) {
        if (version == null || version.signum() <= 0) {
            throw new IllegalArgumentException("version must be positive");
        }
        BigInteger radix = BigInteger.valueOf(RADIX);
        StringBuilder encoded = new StringBuilder();
        BigInteger remaining = version;
        while (remaining.signum() > 0) {
            BigInteger[] division = remaining.divideAndRemainder(radix);
            encoded.insert(0, Character.toChars(SYMBOLS[division[1].intValue()]));
            remaining = division[0];
        }
        return encoded.toString();
    }

    static ParsedGuide parseGuide(String content) {
        if (!content.startsWith(MAGIC_GUIDE)) {
            throw malformed(ArmorException.Reason.INVALID_MAGIC, "Wind text magic guide is invalid");
        }

        int offset = MAGIC_GUIDE.length();
        int digitCount = 0;
        BigInteger version = BigInteger.ZERO;
        while (offset < content.length()) {
            char current = content.charAt(offset);
            if (Character.isHighSurrogate(current)) {
                if (offset + 1 >= content.length() || !Character.isLowSurrogate(content.charAt(offset + 1))) {
                    throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version contains an unpaired high surrogate");
                }
            } else if (Character.isLowSurrogate(current)) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version contains an unpaired low surrogate");
            }

            int codePoint = content.codePointAt(offset);
            offset += Character.charCount(codePoint);
            if (codePoint == TERMINATOR) {
                if (digitCount == 0 || version.signum() == 0) {
                    throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version must be a positive integer");
                }
                return new ParsedGuide(version, offset);
            }

            Integer digit = INDEXES.get(codePoint);
            if (digit == null) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version contains a code point outside the frozen alphabet");
            }
            if (digitCount == 0 && digit == 0) {
                throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version must not contain a leading zero");
            }
            if (++digitCount > MAX_VERSION_DIGITS) {
                throw malformed(ArmorException.Reason.INVALID_INPUT, "Wind version exceeds the safe scan limit");
            }
            version = version.shiftLeft(6).add(BigInteger.valueOf(digit));
        }
        throw malformed(ArmorException.Reason.INVALID_TEXT, "Wind version terminator is missing");
    }

    private static Map<Integer, Integer> buildIndexes() {
        if (SYMBOLS.length != RADIX) {
            throw new IllegalStateException("Wind version alphabet must contain 64 code points");
        }
        if (!ALPHABET_SHA256.equals(sha256(ALPHABET.getBytes(StandardCharsets.UTF_8)))) {
            throw new IllegalStateException("Wind version alphabet hash does not match the frozen sequence");
        }
        Set<Integer> unique = new HashSet<>(RADIX);
        Map<Integer, Integer> indexes = new HashMap<>(RADIX * 2);
        for (int index = 0; index < SYMBOLS.length; index++) {
            int symbol = SYMBOLS[index];
            if (symbol == TERMINATOR) {
                throw new IllegalStateException("Wind version terminator must not be part of the alphabet");
            }
            if (!unique.add(symbol)) {
                throw new IllegalStateException("Wind version alphabet contains duplicate code points");
            }
            indexes.put(symbol, index);
        }
        return Map.copyOf(indexes);
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static ArmorException malformed(ArmorException.Reason reason, String message) {
        return new ArmorException(reason, message);
    }

    record ParsedGuide(BigInteger version, int bodyOffset) {
    }
}
