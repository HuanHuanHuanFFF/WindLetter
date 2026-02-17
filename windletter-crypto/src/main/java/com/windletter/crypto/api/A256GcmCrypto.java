package com.windletter.crypto.api;

/**
 * Contract comment in English.
 */
public interface A256GcmCrypto {

    /**
     * Contract comment in English.
     *
     * @param key 32 byteskey
     * @param iv 12 bytes IV(Nonce)
     * @param aad a ad parameter.
     * @param plaintext plaintextbytes
     * @return return value.
     */
    AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext);

    /**
     * Contract comment in English.
     *
     * @param key 32 byteskey
     * @param iv 12 bytes IV(Nonce)
     * @param aad a ad parameter.
     * @param ciphertext ciphertextbytes
     * @param tag 16 bytesauthentication tag
     * @return return value.
     */
    byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag);
}
