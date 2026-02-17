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
     */
    byte[] extract(byte[] salt, byte[] ikm);

    /**
     * HKDF-Expand (HMAC-SHA256).
     *
     * @param prk output of extract (PRK)
     * @param info optional context info, may be null or empty array
     * @param length output length (bytes)
     * @return OKM (length bytes)
     * @throws IllegalArgumentException if prk is invalid, info is oversized, or length is out of supported range
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
     * @throws IllegalArgumentException if extract/expand input constraints are violated
     */
    byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length);
}
