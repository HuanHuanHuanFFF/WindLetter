package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class BouncyCastleSha256CryptoTest {

    private final BouncyCastleSha256Crypto crypto = new BouncyCastleSha256Crypto();

    @Test
    void shouldMatchKnownVectorForAbc() {
        byte[] input = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hex("ba7816bf8f01cfea414140de5dae2223"
                + "b00361a396177a9cb410ff61f20015ad");

        byte[] actual = crypto.digest(input);

        assertArrayEquals(expected, actual);
    }

    @Test
    void shouldRejectNullInput() {
        assertThrows(IllegalArgumentException.class, () -> crypto.digest(null));
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
