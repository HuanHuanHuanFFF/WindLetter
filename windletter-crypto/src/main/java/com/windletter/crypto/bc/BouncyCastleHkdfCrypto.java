package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.util.Arrays;

/**
 * Bouncy Castle-based HKDF-SHA256 implementation.
 */
public final class BouncyCastleHkdfCrypto implements HkdfCrypto {

    /**
     * SHA-256 digest length (bytes).
     */
    private static final int HASH_LEN = 32;
    /**
     * RFC 5869 limit: maximum output length = 255 * HashLen.
     */
    private static final int MAX_OKM_LENGTH = 255 * HASH_LEN;

    private static HKDFBytesGenerator newHkdf() {
        return new HKDFBytesGenerator(new SHA256Digest());
    }

    @Override
    public byte[] extract(byte[] salt, byte[] ikm) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("ikm must not be empty");
        }
        try {
            byte[] prk = newHkdf().extractPRK(salt, ikm);
            return prk;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to extract HKDF PRK", e);
        }
    }

    @Override
    public byte[] expand(byte[] prk, byte[] info, int length) {
        if (prk == null || prk.length == 0) {
            throw new IllegalArgumentException("prk must not be empty");
        }
        validateLength(length);
        byte[] normalizedInfo = normalizeInfo(info);

        try {
            HKDFBytesGenerator hkdf = newHkdf();
            hkdf.init(HKDFParameters.skipExtractParameters(prk, normalizedInfo));
            byte[] out = new byte[length];
            hkdf.generateBytes(out, 0, length);
            return out;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to expand HKDF output", e);
        }
    }

    @Override
    public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("ikm must not be empty");
        }
        validateLength(length);
        byte[] normalizedInfo = normalizeInfo(info);

        try {
            HKDFBytesGenerator hkdf = newHkdf();
            hkdf.init(new HKDFParameters(ikm, salt, normalizedInfo));
            byte[] out = new byte[length];
            hkdf.generateBytes(out, 0, length);
            return out;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to derive HKDF output", e);
        }
    }

    private static void validateLength(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be > 0");
        }
        if (length > MAX_OKM_LENGTH) {
            throw new IllegalArgumentException("length must be <= " + MAX_OKM_LENGTH);
        }
    }

    private static byte[] normalizeInfo(byte[] info) {
        if (info == null) {
            return new byte[0];
        }
        return Arrays.copyOf(info, info.length);
    }
}
