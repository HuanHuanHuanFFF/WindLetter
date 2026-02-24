package com.windletter.crypto.api;

/**
 * HKDF-SHA256 primitive capability interface.
 * <p>
 * Provides three HKDF capabilities: extract, expand, and one-shot derive.
 */
public interface HkdfCrypto {

    /**
     * HKDF-Extract (HMAC-SHA256).
     *
     * @param salt optional salt, may be null or empty array
     * @param ikm input keying material
     * @return PRK (32 bytes)
     * @throws IllegalArgumentException if ikm is null/empty
     * @throws CryptoOperationException if extraction fails in the underlying crypto provider
     */
    byte[] extract(byte[] salt, byte[] ikm);

    /**
     * HKDF-Expand (HMAC-SHA256).
     *
     * @param prk pseudo-random key, typically output of extract (must be non-empty)
     * @param info optional context info, may be null or empty array
     * @param length output length (bytes)
     * @return OKM (length bytes)
     * @throws IllegalArgumentException if prk is invalid or length is out of supported range (1..8160)
     * @throws CryptoOperationException if expansion fails in the underlying crypto provider
     */
    byte[] expand(byte[] prk, byte[] info, int length);

    /**
     * One-shot derivation: extract first, then expand.
     *
     * @param salt optional salt, may be null or empty array
     * @param ikm input keying material
     * @param info optional context info, may be null or empty array
     * @param length output length (bytes)
     * @return derived result (length bytes)
     * Equivalent to extract(salt, ikm) + expand(prk, info, length).
     * @throws IllegalArgumentException if extract/expand input constraints are violated
     * @throws CryptoOperationException if derivation fails in the underlying crypto provider
     */
    byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length);
}
