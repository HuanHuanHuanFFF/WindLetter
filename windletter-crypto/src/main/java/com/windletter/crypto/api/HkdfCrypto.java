package com.windletter.crypto.api;

/**
 * HKDF-SHA256 原语能力接口。
 * <p>
 * 提供 HKDF 的三类能力：extract、expand 与一体化 derive。
 */
public interface HkdfCrypto {

    /**
     * HKDF-Extract (HMAC-SHA256)。
     *
     * @param salt 可选 salt，允许为 null 或空数组
     * @param ikm 输入密钥材料
     * @return PRK（32 字节）
     */
    byte[] extract(byte[] salt, byte[] ikm);

    /**
     * HKDF-Expand (HMAC-SHA256)。
     *
     * @param prk extract 输出（PRK）
     * @param info 可选上下文信息，允许为 null 或空数组
     * @param length 输出长度（字节）
     * @return OKM（length 字节）
     */
    byte[] expand(byte[] prk, byte[] info, int length);

    /**
     * 一体化派生：先 extract，再 expand。
     *
     * @param salt 可选 salt，允许为 null 或空数组
     * @param ikm 输入密钥材料
     * @param info 可选上下文信息，允许为 null 或空数组
     * @param length 输出长度（字节）
     * @return 派生结果（length 字节）
     */
    byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length);
}
