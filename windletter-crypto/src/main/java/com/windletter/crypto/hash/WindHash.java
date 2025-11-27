package com.windletter.crypto.hash;

import com.windletter.crypto.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * SHA-256 and HKDF-SHA256 helpers.
 * SHA-256 �� HKDF-SHA256 �Ĺ��ߡ�
 */
public class WindHash {
    private static final String SHA_256 = "SHA-256";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HASH_LEN = 32;

    public byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            return md.digest(data == null ? new byte[0] : data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-256 not available", e);
        }
    }

    public byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length <= 0) {
            throw new CryptoException("HKDF output length must be positive");
        }
        if (length > 255 * HASH_LEN) {
            throw new CryptoException("HKDF output length too large");
        }
        byte[] realSalt = salt == null ? new byte[HASH_LEN] : salt;
        byte[] prk = hmac(realSalt, ikm == null ? new byte[0] : ikm);
        int n = (int) Math.ceil((double) length / HASH_LEN);
        byte[] t = new byte[0];
        byte[] okm = new byte[length];
        int pos = 0;
        byte[] realInfo = info == null ? new byte[0] : info;
        for (int i = 1; i <= n; i++) {
            byte[] input = concat(t, realInfo, new byte[]{(byte) i});
            t = hmac(prk, input);
            int copyLen = Math.min(HASH_LEN, length - pos);
            System.arraycopy(t, 0, okm, pos, copyLen);
            pos += copyLen;
        }
        return okm;
    }

    private byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC-SHA256 failed", e);
        }
    }

    private byte[] concat(byte[]... parts) {
        int total = Arrays.stream(parts).mapToInt(p -> p.length).sum();
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, offset, p.length);
            offset += p.length;
        }
        return out;
    }
}