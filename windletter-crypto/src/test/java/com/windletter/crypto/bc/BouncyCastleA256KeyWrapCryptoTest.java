package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.CryptoOperationException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class BouncyCastleA256KeyWrapCryptoTest {

    private final BouncyCastleA256KeyWrapCrypto crypto = new BouncyCastleA256KeyWrapCrypto();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    void shouldWrapAndUnwrapRoundTrip() {
        byte[] kek = randomBytes(32);
        byte[] cek = randomBytes(32);

        byte[] wrapped = crypto.wrap(kek, cek);
        byte[] unwrapped = crypto.unwrap(kek, wrapped);

        assertEquals(40, wrapped.length);
        assertArrayEquals(cek, unwrapped);
    }

    @Test
    void shouldRejectTooShortPlaintextKey() {
        byte[] kek = randomBytes(32);
        assertThrows(IllegalArgumentException.class, () -> crypto.wrap(kek, randomBytes(8)));
    }

    @Test
    void shouldRejectTooShortWrappedKey() {
        byte[] kek = randomBytes(32);
        assertThrows(IllegalArgumentException.class, () -> crypto.unwrap(kek, randomBytes(16)));
    }

    @Test
    void shouldThrowCryptoOperationExceptionWhenKekDoesNotMatch() {
        byte[] kek1 = randomBytes(32);
        byte[] kek2 = randomBytes(32);
        byte[] cek = randomBytes(32);

        byte[] wrapped = crypto.wrap(kek1, cek);
        assertThrows(CryptoOperationException.class, () -> crypto.unwrap(kek2, wrapped));
    }

    @Test
    void shouldMatchRfc3394Aes256KeyWrapTestVector() {
        byte[] kek = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        byte[] keyToWrap = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        byte[] expectedWrapped = hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

        byte[] wrapped = crypto.wrap(kek, keyToWrap);
        byte[] unwrapped = crypto.unwrap(kek, expectedWrapped);

        assertArrayEquals(expectedWrapped, wrapped);
        assertArrayEquals(keyToWrap, unwrapped);
    }

    private byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        secureRandom.nextBytes(out);
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
