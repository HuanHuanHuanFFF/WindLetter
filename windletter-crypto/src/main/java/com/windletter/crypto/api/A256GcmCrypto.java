package com.windletter.crypto.api;

/**
 * A256GCM (AES-GCM with 256-bit key) capability interface.
 */
public interface A256GcmCrypto {

    /**
     * Performs A256GCM encryption.
     *
     * @param key 32-byte key
     * @param iv 12-byte IV (nonce)
     * @param aad optional AAD, may be null
     * @param plaintext plaintext bytes
     * @return ciphertext and 16-byte authentication tag
     */
    AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext);

    /**
     * Performs A256GCM decryption.
     *
     * @param key 32-byte key
     * @param iv 12-byte IV (nonce)
     * @param aad optional AAD, may be null
     * @param ciphertext ciphertext bytes
     * @param tag 16-byte authentication tag
     * @return decrypted plaintext bytes
     */
    byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag);
}
