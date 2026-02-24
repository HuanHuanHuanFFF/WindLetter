package com.windletter.crypto.bc;

import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BouncyCastleEd25519CryptoTest {

    private final BouncyCastleEd25519Crypto crypto = new BouncyCastleEd25519Crypto();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    void shouldRejectInvalidInputLength() {
        byte[] message = randomBytes(32);

        assertThrows(IllegalArgumentException.class, () -> crypto.sign((Ed25519PrivateKeyHandle) null, message));
        assertThrows(IllegalArgumentException.class, () -> crypto.importPrivateKey(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[31], message, new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[32], message, new byte[63]));
    }

    @Test
    void shouldRejectNullMessage() {
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            assertThrows(IllegalArgumentException.class, () -> crypto.sign(privateKey, null));
        }
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[32], null, new byte[64]));
    }

    @Test
    void shouldGenerate32BytePublicKeyFromPrivateKeyHandle() {
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            assertEquals(32, privateKey.publicKey().length);
        }
    }

    @Test
    void shouldSignAndVerify() {
        byte[] message = randomBytes(64);
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            byte[] signature = crypto.sign(privateKey, message);

            assertEquals(64, signature.length);
            assertTrue(crypto.verify(privateKey.publicKey(), message, signature));
        }
    }

    @Test
    void shouldFailVerifyWhenMessageTampered() {
        byte[] message = randomBytes(64);
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            byte[] signature = crypto.sign(privateKey, message);
            byte[] tamperedMessage = cloneAndFlip(message);

            assertFalse(crypto.verify(privateKey.publicKey(), tamperedMessage, signature));
        }
    }

    @Test
    void shouldFailVerifyWhenSignatureTampered() {
        byte[] message = randomBytes(64);
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            byte[] signature = crypto.sign(privateKey, message);
            byte[] tamperedSignature = cloneAndFlip(signature);

            assertFalse(crypto.verify(privateKey.publicKey(), message, tamperedSignature));
        }
    }

    @Test
    void shouldFailVerifyWhenPublicKeyTampered() {
        byte[] message = randomBytes(64);
        try (
                Ed25519PrivateKeyHandle signer = crypto.generatePrivateKey();
                Ed25519PrivateKeyHandle another = crypto.generatePrivateKey()
        ) {
            byte[] signature = crypto.sign(signer, message);

            assertFalse(crypto.verify(another.publicKey(), message, signature));
        }
    }

    @Test
    void shouldVerifyRfc8032TestVector1() {
        byte[] publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] message = new byte[0];
        byte[] signature = hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );

        assertTrue(crypto.verify(publicKey, message, signature));
    }

    @Test
    void shouldImportPrivateKeyAndSignRfc8032TestVector1() {
        byte[] privateKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] expectedPublicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] message = new byte[0];
        byte[] expectedSignature = hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );

        byte[] signature;
        try (Ed25519PrivateKeyHandle imported = crypto.importPrivateKey(privateKey)) {
            assertArrayEquals(expectedPublicKey, imported.publicKey());
            signature = crypto.sign(imported, message);
        }

        assertArrayEquals(expectedSignature, signature);
        assertTrue(crypto.verify(expectedPublicKey, message, signature));
    }

    @Test
    void shouldRejectClosedPrivateKeyHandle() {
        byte[] message = randomBytes(32);
        try (Ed25519PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            privateKey.close();

            assertThrows(IllegalStateException.class, privateKey::publicKey);
            assertThrows(IllegalStateException.class, () -> crypto.sign(privateKey, message));
        }
    }

    @Test
    void shouldRejectForeignPrivateKeyHandle() {
        byte[] message = randomBytes(32);
        Ed25519PrivateKeyHandle foreignHandle = new Ed25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
                // no-op
            }
        };

        assertThrows(IllegalArgumentException.class, () -> crypto.sign(foreignHandle, message));
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
