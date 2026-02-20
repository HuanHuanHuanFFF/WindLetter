package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768KeyPair;
import org.junit.jupiter.api.Test;

class BouncyCastleMLKem768CryptoTest {

    private final BouncyCastleMLKem768Crypto crypto = new BouncyCastleMLKem768Crypto();

    @Test
    void shouldGenerateKeyPairWithExpectedLength() {
        MLKem768KeyPair keyPair = crypto.generateKeyPair();

        assertEquals(MLKem768KeyPair.PRIVATE_KEY_LEN, keyPair.privateKey().length);
        assertEquals(MLKem768KeyPair.PUBLIC_KEY_LEN, keyPair.publicKey().length);
    }

    @Test
    void shouldEncapsulateAndDecapsulate() {
        MLKem768KeyPair keyPair = crypto.generateKeyPair();
        MLKem768Encapsulation encapsulation = crypto.encapsulate(keyPair.publicKey());
        byte[] decapsulatedSecret = crypto.decapsulate(keyPair.privateKey(), encapsulation.ciphertext());

        assertEquals(MLKem768Encapsulation.CIPHERTEXT_LEN, encapsulation.ciphertext().length);
        assertEquals(MLKem768Encapsulation.SHARED_SECRET_LEN, encapsulation.sharedSecret().length);
        assertArrayEquals(encapsulation.sharedSecret(), decapsulatedSecret);
    }

    @Test
    void shouldFailSharedSecretMatchWhenCiphertextTampered() {
        MLKem768KeyPair keyPair = crypto.generateKeyPair();
        MLKem768Encapsulation encapsulation = crypto.encapsulate(keyPair.publicKey());
        byte[] tamperedCiphertext = cloneAndFlip(encapsulation.ciphertext());
        byte[] decapsulatedSecret = crypto.decapsulate(keyPair.privateKey(), tamperedCiphertext);

        assertFalse(java.util.Arrays.equals(encapsulation.sharedSecret(), decapsulatedSecret));
    }

    @Test
    void shouldRejectInvalidInputLength() {
        assertThrows(IllegalArgumentException.class, () -> crypto.encapsulate(new byte[MLKem768KeyPair.PUBLIC_KEY_LEN - 1]));
        assertThrows(
            IllegalArgumentException.class,
            () -> crypto.decapsulate(new byte[MLKem768KeyPair.PRIVATE_KEY_LEN - 1], new byte[MLKem768Encapsulation.CIPHERTEXT_LEN])
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> crypto.decapsulate(new byte[MLKem768KeyPair.PRIVATE_KEY_LEN], new byte[MLKem768Encapsulation.CIPHERTEXT_LEN - 1])
        );
    }

    private static byte[] cloneAndFlip(byte[] value) {
        byte[] out = value.clone();
        if (out.length > 0) {
            out[0] ^= 0x01;
        }
        return out;
    }
}
