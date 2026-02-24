package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Tests for BouncyCastle A256GCM implementation behavior and input validation.
 */
class BouncyCastleA256GcmCryptoTest {

    private final BouncyCastleA256GcmCrypto crypto = new BouncyCastleA256GcmCrypto();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    void shouldEncryptAndDecryptRoundTrip() {
        byte[] key = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(24);
        byte[] plaintext = randomBytes(64);

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);
        byte[] decrypted = crypto.decrypt(key, iv, aad, encrypted.ciphertext(), encrypted.tag());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldFailWhenAadTampered() {
        byte[] key = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(24);
        byte[] plaintext = randomBytes(64);

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);
        byte[] tamperedAad = cloneAndFlip(aad);

        assertThrows(
            CryptoOperationException.class,
            () -> crypto.decrypt(key, iv, tamperedAad, encrypted.ciphertext(), encrypted.tag())
        );
    }

    @Test
    void shouldFailWhenIvTampered() {
        byte[] key = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(24);
        byte[] plaintext = randomBytes(64);

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);
        byte[] tamperedIv = cloneAndFlip(iv);

        assertThrows(
            CryptoOperationException.class,
            () -> crypto.decrypt(key, tamperedIv, aad, encrypted.ciphertext(), encrypted.tag())
        );
    }

    @Test
    void shouldFailWhenCiphertextTampered() {
        byte[] key = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(24);
        byte[] plaintext = randomBytes(64);

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);
        byte[] tamperedCiphertext = cloneAndFlip(encrypted.ciphertext());

        assertThrows(
            CryptoOperationException.class,
            () -> crypto.decrypt(key, iv, aad, tamperedCiphertext, encrypted.tag())
        );
    }

    @Test
    void shouldFailWhenTagTampered() {
        byte[] key = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(24);
        byte[] plaintext = randomBytes(64);

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);
        byte[] tamperedTag = cloneAndFlip(encrypted.tag());

        assertThrows(
            CryptoOperationException.class,
            () -> crypto.decrypt(key, iv, aad, encrypted.ciphertext(), tamperedTag)
        );
    }

    @Test
    void shouldValidateInputLengths() {
        byte[] iv = randomBytes(12);
        byte[] aad = randomBytes(8);
        byte[] plaintext = randomBytes(16);

        assertThrows(IllegalArgumentException.class, () -> crypto.encrypt(randomBytes(31), iv, aad, plaintext));
        assertThrows(IllegalArgumentException.class, () -> crypto.encrypt(randomBytes(32), randomBytes(11), aad, plaintext));
        assertThrows(IllegalArgumentException.class, () -> crypto.encrypt(randomBytes(32), iv, aad, null));

        assertThrows(IllegalArgumentException.class, () -> crypto.decrypt(randomBytes(31), iv, aad, randomBytes(16), randomBytes(16)));
        assertThrows(IllegalArgumentException.class, () -> crypto.decrypt(randomBytes(32), randomBytes(11), aad, randomBytes(16), randomBytes(16)));
        assertThrows(IllegalArgumentException.class, () -> crypto.decrypt(randomBytes(32), iv, aad, null, randomBytes(16)));
        assertThrows(IllegalArgumentException.class, () -> crypto.decrypt(randomBytes(32), iv, aad, randomBytes(16), randomBytes(15)));
    }

    @Test
    void shouldMatchNistAesGcm256TestVector() {
        byte[] key = hex("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] iv = hex("000000000000000000000000");
        byte[] aad = new byte[0];
        byte[] plaintext = hex("00000000000000000000000000000000");
        byte[] expectedCiphertext = hex("cea7403d4d606b6e074ec5d3baf39d18");
        byte[] expectedTag = hex("d0d1c8a799996bf0265b98b5d48ab919");

        AeadCiphertext encrypted = crypto.encrypt(key, iv, aad, plaintext);

        assertArrayEquals(expectedCiphertext, encrypted.ciphertext());
        assertArrayEquals(expectedTag, encrypted.tag());
        assertArrayEquals(plaintext, crypto.decrypt(key, iv, aad, encrypted.ciphertext(), encrypted.tag()));
    }

    private byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        secureRandom.nextBytes(out);
        return out;
    }

    private static byte[] cloneAndFlip(byte[] value) {
        byte[] out = value.clone();
        if (out.length > 0) {
            out[0] ^= 0x01;
        }
        return out;
    }

    private static byte[] hex(String value) {
        int len = value.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
        }
        return out;
    }
}
