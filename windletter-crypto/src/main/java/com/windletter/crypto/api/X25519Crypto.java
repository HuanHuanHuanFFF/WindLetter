package com.windletter.crypto.api;

/**
 * X25519 primitive capability interface.
 * <p>
 * Used to generate key pairs and compute shared secrets.
 */
public interface X25519Crypto {

    /**
     * Generate an X25519 key pair.
     *
     * @return immutable key pair container with 32-byte private/public key material
     * @throws CryptoOperationException if key generation fails in the underlying crypto provider
     */
    X25519KeyPair generateKeyPair();

    /**
     * Compute X25519 shared secret using local private key and peer public key.
     *
     * @param privateKey 32-byte X25519 private key
     * @param peerPublicKey 32-byte X25519 public key
     * @return 32-byte shared secret
     * @throws IllegalArgumentException if key length constraints are violated
     * @throws CryptoOperationException if shared-secret derivation fails
     */
    byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey);
}
