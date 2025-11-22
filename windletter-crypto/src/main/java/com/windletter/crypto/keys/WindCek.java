package com.windletter.crypto.keys;

import java.util.Arrays;

/**
 * Content Encryption Key (CEK), 32 bytes random per message.
 * 内容加密密钥，每条消息随机 32 字节。
 */
public final class WindCek {
    private final byte[] key;

    public WindCek(byte[] key) {
        this.key = Arrays.copyOf(key, key.length);
    }

    public byte[] getKey() {
        return Arrays.copyOf(key, key.length);
    }
}
