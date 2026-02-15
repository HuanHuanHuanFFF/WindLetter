package com.windletter.crypto.bc;

import com.windletter.crypto.api.HkdfCrypto;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * 基于 Bouncy Castle 的 HKDF-SHA256 实现。
 */
public final class BouncyCastleHkdfCrypto implements HkdfCrypto {

    /**
     * SHA-256 的摘要长度（字节）。
     */
    private static final int HASH_LEN = 32;
    /**
     * RFC 5869 限制：最大输出长度 = 255 * HashLen。
     */
    private static final int MAX_OKM_LENGTH = 255 * HASH_LEN;
    /**
     * 工程约束：限制 info 长度，避免异常超长输入。
     */
    private static final int MAX_INFO_LENGTH = 1024;

    private static HKDFBytesGenerator newHkdf() {
        return new HKDFBytesGenerator(new SHA256Digest());
    }

    @Override
    public byte[] extract(byte[] salt, byte[] ikm) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("ikm must not be empty");
        }
        return newHkdf().extractPRK(salt, ikm);
    }

    @Override
    public byte[] expand(byte[] prk, byte[] info, int length) {
        if (prk == null || prk.length == 0) {
            throw new IllegalArgumentException("prk must not be empty");
        }
        validateLength(length);
        byte[] normalizedInfo = normalizeInfo(info);

        HKDFBytesGenerator hkdf = newHkdf();
        hkdf.init(HKDFParameters.skipExtractParameters(prk, normalizedInfo));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
    }

    @Override
    public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("ikm must not be empty");
        }
        validateLength(length);
        byte[] normalizedInfo = normalizeInfo(info);

        HKDFBytesGenerator hkdf = newHkdf();
        hkdf.init(new HKDFParameters(ikm, salt, normalizedInfo));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
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
        if (info.length > MAX_INFO_LENGTH) {
            throw new IllegalArgumentException("info is too long");
        }
        return Arrays.copyOf(info, info.length);
    }
}
