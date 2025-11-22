package com.windletter.crypto.aead;

import com.windletter.crypto.CryptoException;

/**
 * AES-256-GCM implementation placeholder.
 * AES-256-GCM 的实现占位。
 */
public class AesGcmCipher implements AeadCipher {
    @Override
    public AeadResult encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) throws CryptoException {
        throw new CryptoException("AES-GCM encryption not yet implemented");
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws CryptoException {
        throw new CryptoException("AES-GCM decryption not yet implemented");
    }
}
