package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import org.junit.jupiter.api.Test;

class BouncyCastleX25519CryptoTest {

    private final BouncyCastleX25519Crypto crypto = new BouncyCastleX25519Crypto();

    @Test
    void shouldGenerate32BytePublicKeyFromPrivateKeyHandle() {
        try (X25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            assertEquals(32, privateKey.publicKey().length);
        }
    }

    @Test
    void shouldDeriveSameSharedSecretOnBothSides() {
        try (
            X25519PrivateKeyHandle alice = crypto.generatePrivateKey();
            X25519PrivateKeyHandle bob = crypto.generatePrivateKey()
        ) {
            byte[] s1 = crypto.deriveSharedSecret(alice, bob.publicKey());
            byte[] s2 = crypto.deriveSharedSecret(bob, alice.publicKey());

            assertEquals(32, s1.length);
            assertArrayEquals(s1, s2);
        }
    }

    @Test
    void shouldRejectInvalidKeyLength() {
        try (X25519PrivateKeyHandle alice = crypto.generatePrivateKey()) {
            assertThrows(IllegalArgumentException.class, () -> crypto.deriveSharedSecret(alice, new byte[31]));
        }
        assertThrows(IllegalArgumentException.class, () -> crypto.importPrivateKey(new byte[31]));
    }

    @Test
    void shouldMatchRfc7748TestVector() {
        byte[] alicePrivateKey = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPublicKey = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expectedSharedSecret = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        byte[] sharedSecret;
        try (X25519PrivateKeyHandle privateKey = crypto.importPrivateKey(alicePrivateKey)) {
            sharedSecret = crypto.deriveSharedSecret(privateKey, bobPublicKey);
        }

        assertArrayEquals(expectedSharedSecret, sharedSecret);
    }

    @Test
    void shouldRejectClosedPrivateKeyHandle() {
        try (
            X25519PrivateKeyHandle local = crypto.generatePrivateKey();
            X25519PrivateKeyHandle peer = crypto.generatePrivateKey()
        ) {
            byte[] peerPublicKey = peer.publicKey();

            local.close();

            assertThrows(IllegalStateException.class, local::publicKey);
            assertThrows(IllegalStateException.class, () -> crypto.deriveSharedSecret(local, peerPublicKey));
        }
    }

    @Test
    void shouldRejectForeignPrivateKeyHandle() {
        byte[] peerPublicKey;
        try (X25519PrivateKeyHandle peer = crypto.generatePrivateKey()) {
            peerPublicKey = peer.publicKey();
        }

        X25519PrivateKeyHandle foreignHandle = new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
                // no-op
            }
        };

        assertThrows(IllegalArgumentException.class, () -> crypto.deriveSharedSecret(foreignHandle, peerPublicKey));
    }

    @Test
    void shouldRejectLowOrderPeerPublicKey() {
        try (X25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            byte[] lowOrderPublicKey = new byte[32];
            CryptoOperationException ex = assertThrows(
                CryptoOperationException.class,
                () -> crypto.deriveSharedSecret(privateKey, lowOrderPublicKey)
            );
            assertTrue(ex.getMessage().contains("low-order public key"));
        }
    }

    @Test
    void shouldAllowIdempotentClose() {
        X25519PrivateKeyHandle handle = crypto.generatePrivateKey();
        handle.close();
        assertDoesNotThrow(handle::close);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldPrioritizeClosedHandleOverLowOrderPeerKey() {
        X25519PrivateKeyHandle handle = crypto.generatePrivateKey();
        handle.close();
        assertThrows(IllegalStateException.class, () -> crypto.deriveSharedSecret(handle, new byte[32]));
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
