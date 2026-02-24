package com.windletter.crypto.api;

/**
 * Ed25519 primitive capability interface.
 * <p>
 * Provides key generation, signing, and signature verification.
 * <p>
 * Private key handles are provider-bound and must be consumed by the same crypto implementation family.
 */
public interface Ed25519Crypto {

    /**
     * Generate an Ed25519 private key handle.
     *
     * @return private key handle
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    Ed25519PrivateKeyHandle generatePrivateKey();

    /**
     * Import an Ed25519 private key as a handle.
     *
     * @param privateKey 32-byte Ed25519 private key material
     * @return private key handle
     * @throws IllegalArgumentException if private key length is invalid
     * @throws CryptoOperationException if key import fails in the underlying crypto provider
     */
    Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey);

    /**
     * Sign a message using Ed25519 private key handle.
     *
     * @param privateKey private key handle
     * @param message message bytes to sign
     * @return Ed25519 signature bytes
     * @throws IllegalArgumentException if private key is null, message is null, or privateKey is from another implementation
     * @throws IllegalStateException if private key handle has been closed
     * @throws CryptoOperationException if signing fails in the underlying crypto provider
     */
    byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message);

    /**
     * Verify an Ed25519 signature.
     *
     * @param publicKey 32-byte Ed25519 public key
     * @param message message bytes that were signed
     * @param signature Ed25519 signature bytes (64 bytes)
     * @return {@code true} if signature is valid; otherwise {@code false}
     * Returns {@code false} for cryptographically invalid signatures.
     * @throws IllegalArgumentException if key/signature length is invalid or message is null
     * @throws CryptoOperationException if an unexpected verification error occurs in the underlying crypto provider
     */
    boolean verify(byte[] publicKey, byte[] message, byte[] signature);
}
