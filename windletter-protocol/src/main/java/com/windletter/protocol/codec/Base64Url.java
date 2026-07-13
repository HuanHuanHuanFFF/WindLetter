package com.windletter.protocol.codec;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;

import java.util.Base64;

/**
 * Canonical unpadded Base64URL codec used by protocol parsing and writing.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        return ENCODER.encodeToString(value);
    }

    public static byte[] decodeCanonical(String value, String fieldPath) {
        if (value == null || value.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, fieldPath + " must be non-blank");
        }
        if (!hasOnlyUnpaddedUrlAlphabet(value)) {
            throw malformed(fieldPath + " is not canonical unpadded Base64URL");
        }

        byte[] decoded;
        try {
            decoded = DECODER.decode(value);
        } catch (IllegalArgumentException e) {
            throw malformed(fieldPath + " is not valid Base64URL", e);
        }
        if (!encode(decoded).equals(value)) {
            throw malformed(fieldPath + " must use canonical Base64URL");
        }
        return decoded;
    }

    public static byte[] decodeCanonicalAllowEmpty(String value, String fieldPath) {
        if (value != null && value.isEmpty()) {
            return new byte[0];
        }
        return decodeCanonical(value, fieldPath);
    }

    private static boolean hasOnlyUnpaddedUrlAlphabet(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean valid = c >= 'A' && c <= 'Z'
                    || c >= 'a' && c <= 'z'
                    || c >= '0' && c <= '9'
                    || c == '-'
                    || c == '_';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    private static ProtocolException malformed(String message) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message);
    }

    private static ProtocolException malformed(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message, cause);
    }
}
