package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void shouldMatchRfc5869TestCase2() {
        byte[] ikm = hex(
            "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f"
        );
        byte[] salt = hex(
            "606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        );
        byte[] info = hex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        byte[] expectedPrk = hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        byte[] expectedOkm = hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );

        byte[] prk = hkdf.extract(salt, ikm);
        byte[] okm = hkdf.expand(prk, info, 82);

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
    void shouldAcceptLargeInfo() {
        byte[] prk = new byte[32];
        byte[] longInfo = new byte[10_000];

        byte[] okm1 = hkdf.expand(prk, longInfo, 32);
        byte[] okm2 = hkdf.derive(null, new byte[] {1}, longInfo, 32);

        assertEquals(32, okm1.length);
        assertEquals(32, okm2.length);
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
