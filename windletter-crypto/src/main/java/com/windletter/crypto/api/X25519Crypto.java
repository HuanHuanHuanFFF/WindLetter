package com.windletter.crypto.api;

/**
 * X25519 primitive capability interface.
 * <p>
 * Used to generate/import private key handles and compute shared secrets.
 * <p>
 * Handle objects are provider-bound and must be consumed by the same crypto implementation family.
 */
public interface X25519Crypto {

    /**
     * Generate an X25519 private key handle.
     *
     * @return private key handle
     * This handle can be used for shared-secret derivation and public key export.
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    X25519PrivateKeyHandle generatePrivateKey();

    /**
     * Import an X25519 private key as a handle.
     *
     * @param privateKey 32-byte X25519 private key material
     * @return private key handle
     * @throws IllegalArgumentException if private key length is invalid
     * @throws CryptoOperationException if key import fails in the underlying crypto provider
     */
    X25519PrivateKeyHandle importPrivateKey(byte[] privateKey);

    /**
     * Export the canonical raw encoding of an X25519 private key.
     *
     * @param privateKey private key handle created by this crypto implementation
     * @return caller-owned defensive copy of the 32-byte raw private key
     * The caller is responsible for clearing the returned array after use.
     * @throws IllegalArgumentException if privateKey is null or from another implementation
     * @throws IllegalStateException if private key handle has been closed
     * @throws UnsupportedOperationException if this implementation does not support private-key export
     */
    default byte[] exportPrivateKey(X25519PrivateKeyHandle privateKey) {
        throw new UnsupportedOperationException("private key export is not supported");
    }

    /**
     * Compute X25519 shared secret using local private key handle and peer public key.
     *
     * @param privateKey local private key handle
     * @param peerPublicKey 32-byte X25519 public key
     * @return 32-byte shared secret
     * @throws IllegalArgumentException if key/material constraints are violated, or if privateKey is from another implementation
     * @throws IllegalStateException if private key handle has been closed
     * @throws CryptoOperationException if shared-secret derivation fails or peer public key is low-order
     */
    byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey);
}
