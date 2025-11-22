package com.windletter.crypto.aead;

import com.windletter.crypto.CryptoException;

/**
 * AES-GCM wrapper interface.
 * AES-GCM 的封装接口。
 */
public interface AeadCipher {
    AeadResult encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) throws CryptoException;

    byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws CryptoException;
}
