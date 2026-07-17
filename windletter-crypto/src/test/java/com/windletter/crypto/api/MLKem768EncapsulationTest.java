package com.windletter.crypto.api;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MLKem768EncapsulationTest {

    @Test
    void shouldClearOwnedSharedSecretButKeepCiphertextWhenClosed() {
        byte[] ciphertext = filled(MLKem768Encapsulation.CIPHERTEXT_LEN, (byte) 0x5a);
        byte[] sharedSecret = filled(MLKem768Encapsulation.SHARED_SECRET_LEN, (byte) 0x6b);
        MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(ciphertext, sharedSecret);

        encapsulation.close();

        assertArrayEquals(ciphertext, encapsulation.ciphertext());
        assertArrayEquals(new byte[MLKem768Encapsulation.SHARED_SECRET_LEN], encapsulation.sharedSecret());
    }

    @Test
    void shouldAllowIdempotentClose() {
        MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(
                new byte[MLKem768Encapsulation.CIPHERTEXT_LEN],
                filled(MLKem768Encapsulation.SHARED_SECRET_LEN, (byte) 0x01));

        encapsulation.close();

        assertDoesNotThrow(encapsulation::close);
        assertArrayEquals(new byte[MLKem768Encapsulation.SHARED_SECRET_LEN], encapsulation.sharedSecret());
    }

    @Test
    void shouldDefensivelyCopyConstructorInputsAndAccessors() {
        byte[] ciphertext = filled(MLKem768Encapsulation.CIPHERTEXT_LEN, (byte) 0x11);
        byte[] sharedSecret = filled(MLKem768Encapsulation.SHARED_SECRET_LEN, (byte) 0x22);
        try (MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(ciphertext, sharedSecret)) {
            ciphertext[0] = 0x33;
            sharedSecret[0] = 0x44;
            byte[] returnedCiphertext = encapsulation.ciphertext();
            byte[] returnedSharedSecret = encapsulation.sharedSecret();
            returnedCiphertext[1] = 0x55;
            returnedSharedSecret[1] = 0x66;

            assertEquals((byte) 0x11, encapsulation.ciphertext()[0]);
            assertEquals((byte) 0x11, encapsulation.ciphertext()[1]);
            assertEquals((byte) 0x22, encapsulation.sharedSecret()[0]);
            assertEquals((byte) 0x22, encapsulation.sharedSecret()[1]);
        }
    }

    @Test
    void shouldRetainNullAndLengthValidation() {
        byte[] ciphertext = new byte[MLKem768Encapsulation.CIPHERTEXT_LEN];
        byte[] sharedSecret = new byte[MLKem768Encapsulation.SHARED_SECRET_LEN];

        assertThrows(IllegalArgumentException.class, () -> new MLKem768Encapsulation(null, sharedSecret));
        assertThrows(IllegalArgumentException.class, () -> new MLKem768Encapsulation(ciphertext, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MLKem768Encapsulation(
                        new byte[MLKem768Encapsulation.CIPHERTEXT_LEN - 1], sharedSecret));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MLKem768Encapsulation(
                        new byte[MLKem768Encapsulation.CIPHERTEXT_LEN + 1], sharedSecret));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MLKem768Encapsulation(
                        ciphertext, new byte[MLKem768Encapsulation.SHARED_SECRET_LEN - 1]));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MLKem768Encapsulation(
                        ciphertext, new byte[MLKem768Encapsulation.SHARED_SECRET_LEN + 1]));
    }

    private static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
