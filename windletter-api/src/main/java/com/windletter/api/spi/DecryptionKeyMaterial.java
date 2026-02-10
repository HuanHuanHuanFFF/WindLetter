package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * 解密侧密钥材料。
 *
 * @param keyId 密钥标识
 * @param x25519PrivateKey 可选 X25519 私钥
 * @param mlkem768PrivateKey 可选 ML-KEM-768 私钥
 * @param metadata 可扩展元数据
 */
public record DecryptionKeyMaterial(
    String keyId,
    byte[] x25519PrivateKey,
    byte[] mlkem768PrivateKey,
    Map<String, String> metadata
) {

    public DecryptionKeyMaterial {
        keyId = SpiChecks.requireNonBlank(keyId, "keyId");
        // 至少包含一种可用解密私钥。
        if (x25519PrivateKey == null && mlkem768PrivateKey == null) {
            throw new IllegalArgumentException("at least one private key is required");
        }
        x25519PrivateKey = copyNullable(x25519PrivateKey);
        mlkem768PrivateKey = copyNullable(mlkem768PrivateKey);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] x25519PrivateKey() {
        // 返回副本，避免泄露内部可变数组。
        return copyNullable(x25519PrivateKey);
    }

    @Override
    public byte[] mlkem768PrivateKey() {
        // 返回副本，避免泄露内部可变数组。
        return copyNullable(mlkem768PrivateKey);
    }

    private static byte[] copyNullable(byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }
}
