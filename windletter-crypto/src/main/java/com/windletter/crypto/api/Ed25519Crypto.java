package com.windletter.crypto.api;

/**
 * Ed25519 primitive capability interface.
 * <p>
 * Provides key generation, signing, and signature verification.
 */
public interface Ed25519Crypto {

    /**
     * Generate an Ed25519 key pair.
     *
     * @return immutable key pair container with 32-byte private/public key material
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    Ed25519KeyPair generateKeyPair();

    /**
     * Sign a message using Ed25519 private key material.
     *
     * @param privateKey 32-byte Ed25519 private key
     * @param message message bytes to sign
     * @return Ed25519 signature bytes
     * @throws IllegalArgumentException if private key length is invalid or message is null
     * @throws CryptoOperationException if signing fails in the underlying crypto provider
     */
    byte[] sign(byte[] privateKey, byte[] message);

    /**
     * Verify an Ed25519 signature.
     *
     * @param publicKey 32-byte Ed25519 public key
     * @param message message bytes that were signed
     * @param signature Ed25519 signature bytes (64 bytes)
     * @return {@code true} if signature is valid; otherwise {@code false}
     * @throws IllegalArgumentException if key/signature length is invalid or message is null
     * @throws CryptoOperationException if an unexpected verification error occurs in the underlying crypto provider
     */
    boolean verify(byte[] publicKey, byte[] message, byte[] signature);
}
