package com.windletter.crypto.bc;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * Bouncy Castle-based A256GCM implementation.
 */
public final class BouncyCastleA256GcmCrypto implements A256GcmCrypto {

    private static final int TAG_BYTES_LEN = 16;

    private static GCMModeCipher newGcm() {
        return GCMBlockCipher.newInstance(AESEngine.newInstance());
    }

    @Override
    public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
        validateKey(key);
        validateIv(iv);
        validatePlaintext(plaintext);
        try {
            GCMModeCipher gcm = newGcm();
            AEADParameters params = new AEADParameters(new KeyParameter(key),
                    TAG_BYTES_LEN * 8, iv, aad);
            gcm.init(true, params);
            byte[] ciphertextTag = new byte[gcm.getOutputSize(plaintext.length)];
            int len = gcm.processBytes(plaintext, 0, plaintext.length, ciphertextTag, 0);
            len += gcm.doFinal(ciphertextTag, len);
            byte[] ciphertext = Arrays.copyOfRange(ciphertextTag, 0, len - TAG_BYTES_LEN);
            byte[] tag = Arrays.copyOfRange(ciphertextTag, len - TAG_BYTES_LEN, len);
            AeadCiphertext result = new AeadCiphertext(ciphertext, tag);
            return result;
        } catch (InvalidCipherTextException | RuntimeException e) {
            throw new CryptoOperationException("failed to encrypt with A256GCM", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
        validateKey(key);
        validateIv(iv);
        validateCiphertext(ciphertext);
        validateTag(tag);
        try {
            byte[] ciphertextTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ciphertextTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ciphertextTag, ciphertext.length, tag.length);

            GCMModeCipher gcm = newGcm();
            AEADParameters params = new AEADParameters(new KeyParameter(key),
                    TAG_BYTES_LEN * 8, iv, aad);
            gcm.init(false, params);
            byte[] plaintext = new byte[gcm.getOutputSize(ciphertextTag.length)];
            int len = gcm.processBytes(ciphertextTag, 0, ciphertextTag.length, plaintext, 0);
            len += gcm.doFinal(plaintext, len);
            plaintext = Arrays.copyOf(plaintext, len);
            return plaintext;
        } catch (InvalidCipherTextException | RuntimeException e) {
            throw new CryptoOperationException("failed to decrypt with A256GCM", e);
        }
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
    }

    private static void validateIv(byte[] iv) {
        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("iv must be 12 bytes");
        }
    }

    private static void validateTag(byte[] tag) {
        if (tag == null || tag.length != 16) {
            throw new IllegalArgumentException("tag must be 16 bytes");
        }
    }

    private static void validatePlaintext(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
    }

    private static void validateCiphertext(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }
    }
}
