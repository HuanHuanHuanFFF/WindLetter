package com.windletter.crypto.api;

/**
 * SHA-256 digest capability interface.
 */
public interface Sha256Crypto {

    /**
     * Compute SHA-256 digest of input bytes.
     *
     * @param input input bytes
     * @return 32-byte SHA-256 digest
     * @throws IllegalArgumentException if input is null
     * @throws CryptoOperationException if hashing fails in the underlying crypto provider
     */
    byte[] digest(byte[] input);
}
