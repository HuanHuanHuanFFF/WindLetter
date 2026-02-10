package com.windletter.api.enums;

/**
 * 密钥封装算法配置。
 */
public enum KeyAlgProfile {
    /** 仅使用 X25519。 */
    X25519,
    /** X25519 + ML-KEM-768 混合方案。 */
    X25519_KYBER768
}
