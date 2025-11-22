package com.windletter.crypto.hash;

import com.windletter.crypto.CryptoException;

/**
 * SHA-256 and HKDF-SHA256 helpers.
 * SHA-256 与 HKDF-SHA256 的工具。
 */
public class WindHash {

    public byte[] sha256(byte[] data) {
        throw new CryptoException("SHA-256 not yet implemented");
    }

    public byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        throw new CryptoException("HKDF-SHA256 not yet implemented");
    }
}
