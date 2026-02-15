package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.X25519KeyPair;
import org.junit.jupiter.api.Test;

class BouncyCastleX25519CryptoTest {

    private final BouncyCastleX25519Crypto crypto = new BouncyCastleX25519Crypto();

    @Test
    void shouldGenerate32ByteKeyPair() {
        X25519KeyPair keyPair = crypto.generateKeyPair();
        assertEquals(32, keyPair.privateKey().length);
        assertEquals(32, keyPair.publicKey().length);
    }

    @Test
    void shouldDeriveSameSharedSecretOnBothSides() {
        X25519KeyPair alice = crypto.generateKeyPair();
        X25519KeyPair bob = crypto.generateKeyPair();

        byte[] s1 = crypto.deriveSharedSecret(alice.privateKey(), bob.publicKey());
        byte[] s2 = crypto.deriveSharedSecret(bob.privateKey(), alice.publicKey());

        assertEquals(32, s1.length);
        assertArrayEquals(s1, s2);
    }

    @Test
    void shouldRejectInvalidKeyLength() {
        X25519KeyPair alice = crypto.generateKeyPair();
        assertThrows(
            IllegalArgumentException.class,
            () -> crypto.deriveSharedSecret(new byte[31], alice.publicKey())
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> crypto.deriveSharedSecret(alice.privateKey(), new byte[31])
        );
    }
}
