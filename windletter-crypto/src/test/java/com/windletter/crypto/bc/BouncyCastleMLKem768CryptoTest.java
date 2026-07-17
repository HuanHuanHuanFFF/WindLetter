package com.windletter.crypto.bc;

import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BouncyCastleMLKem768CryptoTest {

    private final BouncyCastleMLKem768Crypto crypto = new BouncyCastleMLKem768Crypto();

    @Test
    void shouldGeneratePrivateKeyHandleWithExpectedLength() {
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            assertEquals(1184, privateKey.publicKey().length);
        }
    }

    @Test
    void shouldEncapsulateAndDecapsulate() {
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey();
             MLKem768Encapsulation encapsulation = crypto.encapsulate(privateKey.publicKey())) {
            byte[] expectedSecret = encapsulation.sharedSecret();
            byte[] decapsulatedSecret = crypto.decapsulate(privateKey, encapsulation.ciphertext());

            try {
                assertEquals(MLKem768Encapsulation.CIPHERTEXT_LEN, encapsulation.ciphertext().length);
                assertEquals(MLKem768Encapsulation.SHARED_SECRET_LEN, expectedSecret.length);
                assertArrayEquals(expectedSecret, decapsulatedSecret);
            } finally {
                Arrays.fill(expectedSecret, (byte) 0);
                Arrays.fill(decapsulatedSecret, (byte) 0);
            }
        }
    }

    @Test
    void shouldFailSharedSecretMatchWhenCiphertextTampered() {
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey();
             MLKem768Encapsulation encapsulation = crypto.encapsulate(privateKey.publicKey())) {
            byte[] tamperedCiphertext = cloneAndFlip(encapsulation.ciphertext());
            byte[] expectedSecret = encapsulation.sharedSecret();
            byte[] decapsulatedSecret = crypto.decapsulate(privateKey, tamperedCiphertext);

            try {
                assertFalse(Arrays.equals(expectedSecret, decapsulatedSecret));
            } finally {
                Arrays.fill(expectedSecret, (byte) 0);
                Arrays.fill(decapsulatedSecret, (byte) 0);
            }
        }
    }

    @Test
    void shouldRejectInvalidInputLength() {
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey()) {
            assertThrows(IllegalArgumentException.class, () -> crypto.importPrivateKey(new byte[2399]));
            assertThrows(IllegalArgumentException.class, () -> crypto.encapsulate(new byte[1183]));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> crypto.decapsulate((MLKem768PrivateKeyHandle) null, new byte[MLKem768Encapsulation.CIPHERTEXT_LEN])
            );
            assertThrows(IllegalArgumentException.class, () -> crypto.decapsulate(privateKey, new byte[MLKem768Encapsulation.CIPHERTEXT_LEN - 1]));
        }
    }

    @Test
    void shouldImportPrivateKeyAndDecapsulate() {
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(new SecureRandom(), MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
        MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();

        byte[] encodedPrivateKey = privateKey.getEncoded();
        try (MLKem768PrivateKeyHandle imported = crypto.importPrivateKey(encodedPrivateKey);
             MLKem768Encapsulation encapsulation = crypto.encapsulate(imported.publicKey())) {
            byte[] expectedSecret = encapsulation.sharedSecret();
            byte[] decapsulated = crypto.decapsulate(imported, encapsulation.ciphertext());

            try {
                assertArrayEquals(publicKey.getEncoded(), imported.publicKey());
                assertArrayEquals(expectedSecret, decapsulated);
            } finally {
                Arrays.fill(expectedSecret, (byte) 0);
                Arrays.fill(decapsulated, (byte) 0);
            }
        } finally {
            Arrays.fill(encodedPrivateKey, (byte) 0);
        }
    }

    @Test
    void shouldRejectClosedPrivateKeyHandle() {
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey();
             MLKem768Encapsulation encapsulation = crypto.encapsulate(privateKey.publicKey())) {
            privateKey.close();

            assertThrows(IllegalStateException.class, privateKey::publicKey);
            assertThrows(IllegalStateException.class, () -> crypto.decapsulate(privateKey, encapsulation.ciphertext()));
        }
    }

    @Test
    void shouldAllowIdempotentClose() {
        MLKem768PrivateKeyHandle handle = crypto.generatePrivateKey();
        handle.close();
        assertDoesNotThrow(handle::close);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldRejectForeignPrivateKeyHandle() {
        byte[] ciphertext;
        try (MLKem768PrivateKeyHandle privateKey = crypto.generatePrivateKey();
             MLKem768Encapsulation encapsulation = crypto.encapsulate(privateKey.publicKey())) {
            ciphertext = encapsulation.ciphertext();
        }

        MLKem768PrivateKeyHandle foreignHandle = new MLKem768PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[1184];
            }

            @Override
            public void close() {
                // no-op
            }
        };

        assertThrows(IllegalArgumentException.class, () -> crypto.decapsulate(foreignHandle, ciphertext));
    }

    @Test
    void shouldMatchCctvStrcmpOfficialVector() throws IOException {
        Properties vector = loadProperties("vectors/cctv/mlkem768-strcmp-vector1.properties");
        byte[] privateKey = hex(vector.getProperty("dk"));
        byte[] ciphertext = hex(vector.getProperty("c"));
        byte[] expectedSecret = hex(vector.getProperty("k"));

        assertEquals(2400, privateKey.length);
        assertEquals(MLKem768Encapsulation.CIPHERTEXT_LEN, ciphertext.length);
        assertEquals(MLKem768Encapsulation.SHARED_SECRET_LEN, expectedSecret.length);

        byte[] actualSecret = null;
        try {
            try (MLKem768PrivateKeyHandle imported = crypto.importPrivateKey(privateKey)) {
                actualSecret = crypto.decapsulate(imported, ciphertext);
            }

            assertArrayEquals(expectedSecret, actualSecret);
        } finally {
            Arrays.fill(privateKey, (byte) 0);
            Arrays.fill(expectedSecret, (byte) 0);
            if (actualSecret != null) {
                Arrays.fill(actualSecret, (byte) 0);
            }
        }
    }

    private static Properties loadProperties(String resourcePath) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = BouncyCastleMLKem768CryptoTest.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IOException("missing test resource: " + resourcePath);
            }
            properties.load(in);
        }
        return properties;
    }

    private static byte[] hex(String value) {
        int len = value.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
        }
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
