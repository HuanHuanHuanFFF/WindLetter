package com.windletter.crypto.aead;

import com.windletter.crypto.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * AES-256-GCM implementation.
 * AES-256-GCM 的具体实现。
 */
public class AesGcmCipher implements AeadCipher {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final int KEY_LENGTH_BYTES = 32;

    @Override
    public AeadResult encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) throws CryptoException {
        requireKeyLength(key);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] output = cipher.doFinal(plaintext);
            int cipherLen = output.length - TAG_LENGTH_BYTES;
            if (cipherLen < 0) {
                throw new CryptoException("AES-GCM encryption output too short");
            }
            byte[] ciphertext = Arrays.copyOf(output, cipherLen);
            byte[] tag = Arrays.copyOfRange(output, cipherLen, output.length);
            return new AeadResult(ciphertext, tag);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws CryptoException {
        requireKeyLength(key);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            return cipher.doFinal(combined);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM decryption failed", e);
        }
    }

    private void requireKeyLength(byte[] key) {
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            throw new CryptoException("AES-GCM key must be 32 bytes");
        }
    }
}
