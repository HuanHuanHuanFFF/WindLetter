package com.windletter.crypto.kem;

import com.windletter.crypto.CryptoException;

/**
 * ECDH-ES using X25519 for deriving shared secrets.
 * 使用 X25519 的 ECDH-ES 共享密钥派生。
 */
public class X25519KeyAgreement {

    public byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey) {
        throw new CryptoException("X25519 shared secret not yet implemented");
    }
}
