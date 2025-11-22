package com.windletter.core.encoding;

import java.util.Base64;

/**
 * Base64URL helper that always emits unpadded output.
 * 始终输出无填充的 Base64URL 编解码工具。
 */
public final class Base64Url {
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    public static byte[] decode(String text) {
        return DECODER.decode(text);
    }
}
