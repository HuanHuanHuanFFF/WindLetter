package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.windletter.crypto.api.Ed25519KeyPair;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class BouncyCastleEd25519CryptoTest {

    private final BouncyCastleEd25519Crypto crypto = new BouncyCastleEd25519Crypto();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    void shouldRejectInvalidInputLength() {
        byte[] message = randomBytes(32);

        assertThrows(IllegalArgumentException.class, () -> crypto.sign(new byte[31], message));
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[31], message, new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[32], message, new byte[63]));
    }

    @Test
    void shouldRejectNullMessage() {
        assertThrows(IllegalArgumentException.class, () -> crypto.sign(new byte[32], null));
        assertThrows(IllegalArgumentException.class, () -> crypto.verify(new byte[32], null, new byte[64]));
    }

    @Test
    void shouldGenerate32ByteKeyPair() {
        Ed25519KeyPair keyPair = crypto.generateKeyPair();
        assertEquals(32, keyPair.privateKey().length);
        assertEquals(32, keyPair.publicKey().length);
    }

    @Test
    void shouldSignAndVerify() {
        Ed25519KeyPair keyPair = crypto.generateKeyPair();
        byte[] message = randomBytes(64);
        byte[] signature = crypto.sign(keyPair.privateKey(), message);

        assertEquals(64, signature.length);
        assertTrue(crypto.verify(keyPair.publicKey(), message, signature));
    }

    @Test
    void shouldFailVerifyWhenMessageTampered() {
        Ed25519KeyPair keyPair = crypto.generateKeyPair();
        byte[] message = randomBytes(64);
        byte[] signature = crypto.sign(keyPair.privateKey(), message);
        byte[] tamperedMessage = cloneAndFlip(message);

        assertFalse(crypto.verify(keyPair.publicKey(), tamperedMessage, signature));
    }

    @Test
    void shouldFailVerifyWhenSignatureTampered() {
        Ed25519KeyPair keyPair = crypto.generateKeyPair();
        byte[] message = randomBytes(64);
        byte[] signature = crypto.sign(keyPair.privateKey(), message);
        byte[] tamperedSignature = cloneAndFlip(signature);

        assertFalse(crypto.verify(keyPair.publicKey(), message, tamperedSignature));
    }

    @Test
    void shouldFailVerifyWhenPublicKeyTampered() {
        Ed25519KeyPair keyPair = crypto.generateKeyPair();
        byte[] message = randomBytes(64);
        byte[] signature = crypto.sign(keyPair.privateKey(), message);
        byte[] tamperedPublicKey = cloneAndFlip(keyPair.publicKey());

        assertFalse(crypto.verify(tamperedPublicKey, message, signature));
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
}
