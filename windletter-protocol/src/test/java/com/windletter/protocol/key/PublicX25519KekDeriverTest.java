package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicX25519KekDeriverTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] ALICE_PRIVATE = HEX.parseHex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    );
    private static final byte[] BOB_PUBLIC = HEX.parseHex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    private static final byte[] SHARED_SECRET = HEX.parseHex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
    private static final byte[] EXPECTED_PRK = HEX.parseHex(
            "521a3be705d4ae4110c12cd63287e698c224cd8806f3cec048d03be799f10db2"
    );
    private static final byte[] EXPECTED_KEK = HEX.parseHex(
            "277479809bf70197fc456c17b12429319823906852875eb2353482fb3a4e0cb6"
    );

    @Test
    void derivesRfc7748AndHkdfFixedVector() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(x25519, hkdf);

        try (X25519PrivateKeyHandle alice = x25519.importPrivateKey(ALICE_PRIVATE)) {
            byte[] shared = x25519.deriveSharedSecret(alice, BOB_PUBLIC);
            byte[] prk = hkdf.extract("wind".getBytes(StandardCharsets.UTF_8), shared);
            byte[] kek = deriver.derive(alice, BOB_PUBLIC);
            try {
                assertArrayEquals(SHARED_SECRET, shared);
                assertArrayEquals(EXPECTED_PRK, prk);
                assertArrayEquals(EXPECTED_KEK, kek);
            } finally {
                Arrays.fill(shared, (byte) 0);
                Arrays.fill(prk, (byte) 0);
                Arrays.fill(kek, (byte) 0);
            }
        }
    }

    @Test
    void derivesTheSameKekOnBothRealSidesWithoutClosingBorrowedHandles() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                x25519,
                new BouncyCastleHkdfCrypto()
        );
        try (X25519PrivateKeyHandle alice = x25519.generatePrivateKey();
             X25519PrivateKeyHandle bob = x25519.generatePrivateKey()) {
            byte[] senderKek = deriver.derive(alice, bob.publicKey());
            byte[] receiverKek = deriver.derive(bob, alice.publicKey());
            try {
                assertArrayEquals(senderKek, receiverKek);
                assertFalse(allZero(senderKek));
                assertEquals(32, alice.publicKey().length);
                assertEquals(32, bob.publicKey().length);
            } finally {
                Arrays.fill(senderKek, (byte) 0);
                Arrays.fill(receiverKek, (byte) 0);
            }
        }
    }

    @Test
    void preservesLowOrderClosedAndForeignHandleFailureCategories() {
        BouncyCastleX25519Crypto firstCrypto = new BouncyCastleX25519Crypto();
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                firstCrypto,
                new BouncyCastleHkdfCrypto()
        );
        X25519PrivateKeyHandle live = firstCrypto.generatePrivateKey();
        X25519PrivateKeyHandle peer = firstCrypto.generatePrivateKey();
        try {
            assertThrows(CryptoOperationException.class, () -> deriver.derive(live, new byte[32]));

            live.close();
            assertThrows(IllegalStateException.class, () -> deriver.derive(live, peer.publicKey()));
            assertThrows(IllegalArgumentException.class, () -> deriver.derive(DUMMY_HANDLE, peer.publicKey()));
        } finally {
            live.close();
            peer.close();
        }
    }

    @Test
    void passesExactHkdfContextAndClearsSharedSecretAfterSuccess() {
        byte[] shared = filled(32, (byte) 0x41);
        byte[] expectedKek = filled(32, (byte) 0x52);
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(shared);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(expectedKek, null);
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(x25519, hkdf);

        byte[] actual = deriver.derive(DUMMY_HANDLE, filled(32, (byte) 0x63));

        assertSame(expectedKek, actual);
        assertArrayEquals("wind".getBytes(StandardCharsets.UTF_8), hkdf.salt);
        assertArrayEquals("WindLetter v1 KEK | X25519".getBytes(StandardCharsets.UTF_8), hkdf.info);
        assertEquals(32, hkdf.length);
        assertSame(shared, hkdf.ikm);
        assertTrue(allZero(shared));
        Arrays.fill(actual, (byte) 0);
    }

    @Test
    void clearsSharedSecretWhenHkdfThrows() {
        byte[] shared = filled(32, (byte) 0x41);
        CryptoOperationException failure = new CryptoOperationException("hkdf failed");
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                new RecordingX25519Crypto(shared),
                new RecordingHkdfCrypto(null, failure)
        );

        assertSame(failure, assertThrows(
                CryptoOperationException.class,
                () -> deriver.derive(DUMMY_HANDLE, filled(32, (byte) 0x63))
        ));
        assertTrue(allZero(shared));
    }

    @Test
    void rejectsAndClearsMalformedOrZeroSharedSecretsBeforeHkdf() {
        for (byte[] malformed : new byte[][]{new byte[31], new byte[32]}) {
            RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(filled(32, (byte) 1), null);
            PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                    new RecordingX25519Crypto(malformed),
                    hkdf
            );

            assertThrows(RuntimeException.class, () -> deriver.derive(DUMMY_HANDLE, filled(32, (byte) 2)));
            assertEquals(0, hkdf.calls);
            assertTrue(allZero(malformed));
        }
    }

    @Test
    void rejectsMalformedKekAndClearsBothProviderOutputs() {
        byte[] shared = filled(32, (byte) 0x21);
        byte[] malformedKek = filled(31, (byte) 0x32);
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                new RecordingX25519Crypto(shared),
                new RecordingHkdfCrypto(malformedKek, null)
        );

        assertThrows(IllegalStateException.class,
                () -> deriver.derive(DUMMY_HANDLE, filled(32, (byte) 0x43)));
        assertTrue(allZero(shared));
        assertTrue(allZero(malformedKek));
    }

    @Test
    void validatesDependenciesAndInputsBeforeCrypto() {
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(filled(32, (byte) 1));
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(filled(32, (byte) 2), null);
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(x25519, hkdf);

        assertThrows(IllegalArgumentException.class, () -> new PublicX25519KekDeriver(null, hkdf));
        assertThrows(IllegalArgumentException.class, () -> new PublicX25519KekDeriver(x25519, null));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(null, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(DUMMY_HANDLE, null));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(DUMMY_HANDLE, new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(DUMMY_HANDLE, new byte[33]));
        assertEquals(0, x25519.calls);
        assertEquals(0, hkdf.calls);
    }

    private static final X25519PrivateKeyHandle DUMMY_HANDLE = new X25519PrivateKeyHandle() {
        @Override
        public byte[] publicKey() {
            return new byte[32];
        }

        @Override
        public void close() {
        }
    };

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static boolean allZero(byte[] value) {
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static final class RecordingX25519Crypto implements X25519Crypto {
        private final byte[] shared;
        private int calls;

        private RecordingX25519Crypto(byte[] shared) {
            this.shared = shared;
        }

        @Override
        public X25519PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey) {
            calls++;
            return shared;
        }
    }

    private static final class RecordingHkdfCrypto implements HkdfCrypto {
        private final byte[] output;
        private final RuntimeException failure;
        private int calls;
        private byte[] salt;
        private byte[] ikm;
        private byte[] info;
        private int length;

        private RecordingHkdfCrypto(byte[] output, RuntimeException failure) {
            this.output = output;
            this.failure = failure;
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
            calls++;
            this.salt = salt.clone();
            this.ikm = ikm;
            this.info = info.clone();
            this.length = length;
            if (failure != null) {
                throw failure;
            }
            return output;
        }
    }
}
