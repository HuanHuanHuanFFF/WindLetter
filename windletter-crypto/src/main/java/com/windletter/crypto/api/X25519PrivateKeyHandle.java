package com.windletter.crypto.api;

/**
 * Handle for X25519 private key.
 * <p>
 * Private key bytes are not exposed directly.
 * Instances are provider-bound and should only be consumed by matching crypto implementations.
 */
public interface X25519PrivateKeyHandle extends AutoCloseable {

    /**
     * Returns corresponding public key bytes.
     *
     * @return 32-byte public key (defensive copy)
     * @throws IllegalStateException if this handle has been closed
     */
    byte[] publicKey();

    /**
     * Destroys the private key material if possible.
     * This operation should be treated as idempotent by callers.
     */
    @Override
    void close();
}
