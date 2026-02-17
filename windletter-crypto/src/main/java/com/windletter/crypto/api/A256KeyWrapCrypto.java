package com.windletter.crypto.api;

/**
 * A256KW (AES Key Wrap with 256-bit KEK) capability interface.
 */
public interface A256KeyWrapCrypto {

    /**
     * Wrap a plaintext key using KEK.
     *
     * @param kek 32-byte KEK
     * @param keyToWrap key to wrap (length must be a multiple of 8 and at least 16 bytes)
     * @return wrapped result
     * @throws IllegalArgumentException if key length constraints are violated
     * @throws CryptoOperationException if wrapping fails in the underlying crypto provider
     */
    byte[] wrap(byte[] kek, byte[] keyToWrap);

    /**
     * Unwrap a key using KEK.
     *
     * @param kek 32-byte KEK
     * @param wrappedKey wrapped key (length must be a multiple of 8 and at least 24 bytes)
     * @return unwrapped result
     * @throws IllegalArgumentException if key length constraints are violated
     * @throws CryptoOperationException if unwrap fails or integrity checks fail
     */
    byte[] unwrap(byte[] kek, byte[] wrappedKey);
}
