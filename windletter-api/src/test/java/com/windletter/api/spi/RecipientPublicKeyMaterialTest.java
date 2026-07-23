package com.windletter.api.spi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class RecipientPublicKeyMaterialTest {

    @Test
    void shouldRequireX25519PairAndExactly32BytePublicKey() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial(" ", new byte[32], null, null)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", null, null, null)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", new byte[31], null, null)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", new byte[33], null, null)
        );
    }

    @Test
    void shouldRequireMlkem768PairAtomicallyAndExactly1184BytePublicKey() {
        byte[] x25519PublicKey = new byte[32];
        byte[] mlkem768PublicKey = new byte[1184];

        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", x25519PublicKey, null, mlkem768PublicKey)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", x25519PublicKey, " ", mlkem768PublicKey)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", x25519PublicKey, "pq-kid", null)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", x25519PublicKey, "pq-kid", new byte[1183])
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> new RecipientPublicKeyMaterial("x-kid", x25519PublicKey, "pq-kid", new byte[1185])
        );

        RecipientPublicKeyMaterial x25519Only = new RecipientPublicKeyMaterial(
            "x-kid",
            x25519PublicKey,
            null,
            null
        );
        assertNull(x25519Only.mlkem768Kid());
        assertNull(x25519Only.mlkem768PublicKey());
    }

    @Test
    void shouldDefensivelyCopyAllPublicKeyArrays() {
        byte[] x25519Input = keyWithFirstByte(32, 1);
        byte[] mlkem768Input = keyWithFirstByte(1184, 2);
        RecipientPublicKeyMaterial material = new RecipientPublicKeyMaterial(
            "x-kid",
            x25519Input,
            "pq-kid",
            mlkem768Input
        );

        x25519Input[0] = 9;
        mlkem768Input[0] = 9;
        byte[] firstX25519Read = material.x25519PublicKey();
        byte[] firstMlkem768Read = material.mlkem768PublicKey();
        assertArrayEquals(keyWithFirstByte(32, 1), firstX25519Read);
        assertArrayEquals(keyWithFirstByte(1184, 2), firstMlkem768Read);
        assertNotSame(firstX25519Read, material.x25519PublicKey());
        assertNotSame(firstMlkem768Read, material.mlkem768PublicKey());

        firstX25519Read[0] = 7;
        firstMlkem768Read[0] = 7;
        assertArrayEquals(keyWithFirstByte(32, 1), material.x25519PublicKey());
        assertArrayEquals(keyWithFirstByte(1184, 2), material.mlkem768PublicKey());
    }

    private static byte[] keyWithFirstByte(int length, int value) {
        byte[] key = new byte[length];
        key[0] = (byte) value;
        return key;
    }
}
