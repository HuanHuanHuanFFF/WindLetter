package com.windletter.crypto.api;

/**
 * A256KW（AES Key Wrap with 256-bit KEK）能力接口。
 */
public interface A256KeyWrapCrypto {

    /**
     * 使用 KEK 包装明文密钥。
     *
     * @param kek 32 字节 KEK
     * @param keyToWrap 待包装密钥（长度必须是 8 的整数倍且至少 16 字节）
     * @return 包装结果
     */
    byte[] wrap(byte[] kek, byte[] keyToWrap);

    /**
     * 使用 KEK 解包密钥。
     *
     * @param kek 32 字节 KEK
     * @param wrappedKey 包装密钥（长度必须是 8 的整数倍且至少 24 字节）
     * @return 解包结果
     */
    byte[] unwrap(byte[] kek, byte[] wrappedKey);
}
