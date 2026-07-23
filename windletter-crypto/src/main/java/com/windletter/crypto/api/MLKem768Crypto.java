package com.windletter.crypto.api;

/**
 * ML-KEM-768 KEM primitive capability interface.
 * <p>
 * Provides key generation, encapsulation, and decapsulation.
 * <p>
 * Private key handles are provider-bound and must be consumed by the same crypto implementation family.
 */
public interface MLKem768Crypto {

    /**
     * Generate an ML-KEM-768 private key handle.
     *
     * @return private key handle
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    MLKem768PrivateKeyHandle generatePrivateKey();

    /**
     * Import an ML-KEM-768 private key as a handle.
     *
     * @param privateKey ML-KEM-768 private key material (2400 bytes, DK encoding)
     * @return private key handle
     * @throws IllegalArgumentException if private key length is invalid
     * @throws CryptoOperationException if key import fails in the underlying crypto provider
     */
    MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey);

    /**
     * Export the canonical ML-KEM-768 decapsulation-key encoding.
     *
     * @param privateKey private key handle created by this crypto implementation
     * @return caller-owned defensive copy of the 2400-byte FIPS 203 DK encoding
     * The caller is responsible for clearing the returned array after use.
     * @throws IllegalArgumentException if privateKey is null or from another implementation
     * @throws IllegalStateException if private key handle has been closed
     * @throws UnsupportedOperationException if this implementation does not support private-key export
     */
    default byte[] exportPrivateKey(MLKem768PrivateKeyHandle privateKey) {
        throw new UnsupportedOperationException("private key export is not supported");
    }

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
     * @param privateKey ML-KEM-768 private key handle
     * @param ciphertext ML-KEM-768 ciphertext (1088 bytes)
     * @return shared secret (32 bytes)
     * @throws IllegalArgumentException if key/ciphertext length is invalid, or if privateKey is from another implementation
     * @throws IllegalStateException if private key handle has been closed
     * @throws CryptoOperationException if decapsulation fails in the underlying crypto provider
     */
    byte[] decapsulate(MLKem768PrivateKeyHandle privateKey, byte[] ciphertext);

}
