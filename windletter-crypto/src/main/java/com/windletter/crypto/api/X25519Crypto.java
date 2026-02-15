package com.windletter.crypto.api;

/**
 * X25519 原语能力接口。
 * <p>
 * 用于生成密钥对以及计算共享秘密。
 */
public interface X25519Crypto {

    /**
     * 生成 X25519 密钥对。
     */
    X25519KeyPair generateKeyPair();

    /**
     * 使用本地私钥与对端公钥计算 X25519 共享秘密。
     *
     * @param privateKey 32 字节 X25519 私钥
     * @param peerPublicKey 32 字节 X25519 公钥
     * @return 32 字节共享秘密
     */
    byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey);
}
