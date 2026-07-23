package com.windletter.api.spi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class X25519PublicKeyMaterialTest {

    @Test
    void shouldRequireNonBlankKidAndExactly32BytePublicKey() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new X25519PublicKeyMaterial(" ", new byte[32])
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new X25519PublicKeyMaterial("kid", null)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new X25519PublicKeyMaterial("kid", new byte[31])
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new X25519PublicKeyMaterial("kid", new byte[33])
        );
    }

    @Test
    void shouldDefensivelyCopyInputAndAccessor() {
        byte[] input = new byte[32];
        input[0] = 1;
        X25519PublicKeyMaterial material = new X25519PublicKeyMaterial("kid", input);

        input[0] = 9;
        byte[] firstRead = material.publicKey();
        assertArrayEquals(keyWithFirstByte(1), firstRead);
        assertNotSame(firstRead, material.publicKey());

        firstRead[0] = 7;
        assertArrayEquals(keyWithFirstByte(1), material.publicKey());
    }

    private static byte[] keyWithFirstByte(int value) {
        byte[] key = new byte[32];
        key[0] = (byte) value;
        return key;
    }
}
