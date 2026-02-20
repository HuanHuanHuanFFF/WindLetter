package com.windletter.crypto.api;

/**
 * ML-KEM-768 KEM primitive capability interface.
 * <p>
 * Provides key generation, encapsulation, and decapsulation.
 */
public interface MLKem768Crypto {

    /**
     * Generate an ML-KEM-768 key pair.
     *
     * @return immutable key pair container with ML-KEM-768 key material
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    MLKem768KeyPair generateKeyPair();

    /**
     * Encapsulate to a recipient public key.
     *
     * @param publicKey ML-KEM-768 public key (1184 bytes)
     * @return encapsulation output with ciphertext and shared secret
     * @throws IllegalArgumentException if public key length is invalid
     * @throws CryptoOperationException if encapsulation fails in the underlying crypto provider
     */
    MLKem768Encapsulation encapsulate(byte[] publicKey);

    /**
     * Decapsulate a ciphertext using local private key.
     *
     * @param privateKey ML-KEM-768 private key (2400 bytes)
     * @param ciphertext ML-KEM-768 ciphertext (1088 bytes)
     * @return shared secret (32 bytes)
     * @throws IllegalArgumentException if key/ciphertext length is invalid
     * @throws CryptoOperationException if decapsulation fails in the underlying crypto provider
     */
    byte[] decapsulate(byte[] privateKey, byte[] ciphertext);
}
