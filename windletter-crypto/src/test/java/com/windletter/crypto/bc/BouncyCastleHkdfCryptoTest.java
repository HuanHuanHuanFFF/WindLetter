package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class BouncyCastleHkdfCryptoTest {

    private static final int MAX_OKM_LENGTH = 255 * 32;
    private final BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();

    @Test
    void shouldMatchRfc5869TestCase1() {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] expectedPrk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        byte[] prk = hkdf.extract(salt, ikm);
        byte[] okm = hkdf.expand(prk, info, 42);

        assertArrayEquals(expectedPrk, prk);
        assertArrayEquals(expectedOkm, okm);
    }

    @Test
    void shouldProduceSameResultForDeriveAndExtractThenExpand() {
        byte[] ikm = hex("0102030405060708090a");
        byte[] salt = hex("0a0b0c0d0e0f");
        byte[] info = hex("f0f1f2");

        byte[] prk = hkdf.extract(salt, ikm);
        byte[] okm1 = hkdf.expand(prk, info, 32);
        byte[] okm2 = hkdf.derive(salt, ikm, info, 32);

        assertArrayEquals(okm1, okm2);
    }

    @Test
    void shouldTreatNullInfoAsEmptyInfo() {
        byte[] ikm = hex("0102030405060708090a");
        byte[] salt = hex("0a0b0c0d0e0f");

        byte[] okmWithNull = hkdf.derive(salt, ikm, null, 32);
        byte[] okmWithEmpty = hkdf.derive(salt, ikm, new byte[0], 32);

        assertArrayEquals(okmWithNull, okmWithEmpty);
    }

    @Test
    void shouldRejectTooLongLength() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0x11);

        assertThrows(IllegalArgumentException.class, () -> hkdf.expand(prk, null, MAX_OKM_LENGTH + 1));
        assertThrows(IllegalArgumentException.class, () -> hkdf.derive(null, new byte[] {1}, null, MAX_OKM_LENGTH + 1));
    }

    @Test
    void shouldRejectTooLongInfo() {
        byte[] prk = new byte[32];
        byte[] longInfo = new byte[1025];

        assertThrows(IllegalArgumentException.class, () -> hkdf.expand(prk, longInfo, 32));
        assertThrows(IllegalArgumentException.class, () -> hkdf.derive(null, new byte[] {1}, longInfo, 32));
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
