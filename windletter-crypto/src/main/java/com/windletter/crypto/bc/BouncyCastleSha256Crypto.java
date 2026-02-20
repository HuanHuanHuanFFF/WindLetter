package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Sha256Crypto;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Bouncy Castle-based SHA-256 implementation.
 */
public final class BouncyCastleSha256Crypto implements Sha256Crypto {

    private static final int HASH_LEN = 32;

    @Override
    public byte[] digest(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }
        try {
            SHA256Digest sha256 = new SHA256Digest();
            sha256.update(input, 0, input.length);
            byte[] out = new byte[HASH_LEN];
            sha256.doFinal(out, 0);
            return out;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to compute SHA-256 digest", e);
        }
    }
}
