package com.windletter.crypto.bc;

import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BouncyCastlePrivateKeyExportTest {

    private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
    private final BouncyCastleMLKem768Crypto mlKem768 = new BouncyCastleMLKem768Crypto();
    private final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();

    @Test
    void shouldExportGeneratedX25519KeyForRoundTripWithoutAliasing() {
        byte[] encoded = null;
        byte[] secondExport = null;
        try (X25519PrivateKeyHandle generated = x25519.generatePrivateKey()) {
            byte[] expectedPublicKey = generated.publicKey();
            encoded = x25519.exportPrivateKey(generated);

            assertEquals(32, encoded.length);
            try (X25519PrivateKeyHandle restored = x25519.importPrivateKey(encoded)) {
                assertArrayEquals(expectedPublicKey, restored.publicKey());
            }

            encoded[0] ^= 0x01;
            secondExport = x25519.exportPrivateKey(generated);
            try (X25519PrivateKeyHandle restoredAgain = x25519.importPrivateKey(secondExport)) {
                assertArrayEquals(expectedPublicKey, restoredAgain.publicKey());
            }
        } finally {
            clear(encoded);
            clear(secondExport);
        }
    }

    @Test
    void shouldExportGeneratedMlKem768KeyForRoundTripAndDecapsulation() {
        byte[] encoded = null;
        byte[] expectedSecret = null;
        byte[] actualSecret = null;
        try (MLKem768PrivateKeyHandle generated = mlKem768.generatePrivateKey()) {
            byte[] expectedPublicKey = generated.publicKey();
            encoded = mlKem768.exportPrivateKey(generated);

            assertEquals(2400, encoded.length);
            try (MLKem768PrivateKeyHandle restored = mlKem768.importPrivateKey(encoded);
                 MLKem768Encapsulation encapsulation = mlKem768.encapsulate(restored.publicKey())) {
                assertArrayEquals(expectedPublicKey, restored.publicKey());
                expectedSecret = encapsulation.sharedSecret();
                actualSecret = mlKem768.decapsulate(restored, encapsulation.ciphertext());
                assertArrayEquals(expectedSecret, actualSecret);
            }
        } finally {
            clear(encoded);
            clear(expectedSecret);
            clear(actualSecret);
        }
    }

    @Test
    void shouldExportImportedEd25519SeedWithoutAliasing() {
        byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] expectedPublicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] firstExport = null;
        byte[] secondExport = null;
        byte[] message = "WindLetter private-key export".getBytes(StandardCharsets.UTF_8);
        try (Ed25519PrivateKeyHandle imported = ed25519.importPrivateKey(seed)) {
            firstExport = ed25519.exportPrivateKey(imported);
            assertArrayEquals(seed, firstExport);

            firstExport[0] ^= 0x01;
            secondExport = ed25519.exportPrivateKey(imported);
            assertArrayEquals(seed, secondExport);

            try (Ed25519PrivateKeyHandle restored = ed25519.importPrivateKey(secondExport)) {
                assertArrayEquals(expectedPublicKey, restored.publicKey());
                byte[] signature = ed25519.sign(restored, message);
                assertTrue(ed25519.verify(expectedPublicKey, message, signature));
            }
        } finally {
            clear(seed);
            clear(firstExport);
            clear(secondExport);
            clear(message);
        }
    }

    @Test
    void shouldRejectNullForeignAndClosedHandles() {
        assertThrows(IllegalArgumentException.class, () -> x25519.exportPrivateKey(null));
        assertThrows(IllegalArgumentException.class, () -> mlKem768.exportPrivateKey(null));
        assertThrows(IllegalArgumentException.class, () -> ed25519.exportPrivateKey(null));

        X25519PrivateKeyHandle foreignX25519 = new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
            }
        };
        MLKem768PrivateKeyHandle foreignMlKem = new MLKem768PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[1184];
            }

            @Override
            public void close() {
            }
        };
        Ed25519PrivateKeyHandle foreignEd25519 = new Ed25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return new byte[32];
            }

            @Override
            public void close() {
            }
        };

        assertThrows(IllegalArgumentException.class, () -> x25519.exportPrivateKey(foreignX25519));
        assertThrows(IllegalArgumentException.class, () -> mlKem768.exportPrivateKey(foreignMlKem));
        assertThrows(IllegalArgumentException.class, () -> ed25519.exportPrivateKey(foreignEd25519));

        X25519PrivateKeyHandle closedX25519 = x25519.generatePrivateKey();
        MLKem768PrivateKeyHandle closedMlKem = mlKem768.generatePrivateKey();
        Ed25519PrivateKeyHandle closedEd25519 = ed25519.generatePrivateKey();
        closedX25519.close();
        closedMlKem.close();
        closedEd25519.close();

        assertThrows(IllegalStateException.class, () -> x25519.exportPrivateKey(closedX25519));
        assertThrows(IllegalStateException.class, () -> mlKem768.exportPrivateKey(closedMlKem));
        assertThrows(IllegalStateException.class, () -> ed25519.exportPrivateKey(closedEd25519));
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < value.length(); i += 2) {
            out[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
        }
        return out;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
