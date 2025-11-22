package com.windletter.crypto.sign;

import com.windletter.crypto.CryptoException;

/**
 * Ed25519 signing/verification adapter.
 * Ed25519 签名与验签适配器。
 */
public class Ed25519Signer {

    public byte[] sign(byte[] privateKey, byte[] message) {
        throw new CryptoException("Ed25519 signing not yet implemented");
    }

    public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        throw new CryptoException("Ed25519 verification not yet implemented");
    }
}
