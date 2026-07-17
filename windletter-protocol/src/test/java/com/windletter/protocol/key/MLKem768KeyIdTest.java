package com.windletter.protocol.key;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MLKem768KeyIdTest {

    @Test
    void derivesSha256OfRaw1184BytePublicKeyAsCanonicalBase64Url() {
        byte[] publicKey = new byte[1184];
        for (int i = 0; i < publicKey.length; i++) {
            publicKey[i] = (byte) (i & 0xff);
        }
        byte[] originalPublicKey = publicKey.clone();

        String kid = MLKem768KeyId.derive(publicKey);

        assertEquals("7NTPOwdCAmuWvE0fGJTJZ5R3RxDExM43huxxjF4IzVc", kid);
        assertEquals(43, kid.length());
        assertTrue(kid.matches("[A-Za-z0-9_-]{43}"));
        assertFalse(kid.contains("="));
        assertArrayEquals(originalPublicKey, publicKey);
    }

    @Test
    void rejectsAnythingExceptRaw1184Bytes() {
        assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(null));
        assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(new byte[1183]));
        assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(new byte[1185]));
    }
}
