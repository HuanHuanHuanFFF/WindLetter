package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridKekDeriverTest {

    @Test
    void combinesEccBeforePqWithExactHybridInfo() {
        byte[] ssEcc = sequence(0x00, 32);
        byte[] ssPq = sequence(0x20, 32);
        byte[] kek = null;
        try {
            kek = PublicHybridKekDeriver.deriveCombined(
                    new BouncyCastleHkdfCrypto(), ssEcc, ssPq
            );

            assertArrayEquals(
                    HexFormat.of().parseHex(
                            "42299fcde7930ae6fc402785a0c231f37886973394e7123f3e5bf58f3406209c"
                    ),
                    kek
            );
            assertArrayEquals(sequence(0x00, 32), ssEcc);
            assertArrayEquals(sequence(0x20, 32), ssPq);
        } finally {
            Arrays.fill(ssEcc, (byte) 0);
            Arrays.fill(ssPq, (byte) 0);
            clear(kek);
        }
    }

    @Test
    void derivesSameKekOnBothRealSidesWithoutClosingBorrowedHandles() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519,
                mlkem768,
                new BouncyCastleHkdfCrypto()
        );

        try (X25519PrivateKeyHandle senderX = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientPq = mlkem768.generatePrivateKey()) {
            byte[] senderPublic = senderX.publicKey();
            byte[] recipientXPublic = recipientX.publicKey();
            byte[] recipientPqPublic = recipientPq.publicKey();
            byte[] receiverKek = null;
            try (PublicHybridKekDeriver.SenderDerivation sender = deriver.deriveForSender(
                    senderX,
                    recipientXPublic,
                    recipientPqPublic
            )) {
                receiverKek = deriver.deriveForReceiver(
                        recipientX,
                        senderPublic,
                        recipientPq,
                        sender.encapsulationCiphertext()
                );

                assertArrayEquals(sender.kek(), receiverKek);
                assertFalse(allZero(receiverKek));
                assertEquals(32, senderX.publicKey().length);
                assertEquals(32, recipientX.publicKey().length);
                assertEquals(1184, recipientPq.publicKey().length);
            } finally {
                clear(senderPublic);
                clear(recipientXPublic);
                clear(recipientPqPublic);
                clear(receiverKek);
            }
        }
    }

    @Test
    void senderDerivationOwnsCopiesAndCloseOnlyClearsKek() {
        byte[] kek = filled(32, (byte) 0x31);
        byte[] ciphertext = filled(1088, (byte) 0x42);
        PublicHybridKekDeriver.SenderDerivation result =
                new PublicHybridKekDeriver.SenderDerivation(kek, ciphertext);

        kek[0] = 0;
        ciphertext[0] = 0;
        byte[] returnedKek = result.kek();
        byte[] returnedCiphertext = result.encapsulationCiphertext();
        returnedKek[1] = 0;
        returnedCiphertext[1] = 0;

        assertEquals((byte) 0x31, result.kek()[0]);
        assertEquals((byte) 0x31, result.kek()[1]);
        assertEquals((byte) 0x42, result.encapsulationCiphertext()[0]);
        assertEquals((byte) 0x42, result.encapsulationCiphertext()[1]);

        result.close();
        assertDoesNotThrow(result::close);
        assertArrayEquals(new byte[32], result.kek());
        assertArrayEquals(filled(1088, (byte) 0x42), result.encapsulationCiphertext());
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKekDeriver.SenderDerivation(null, new byte[1088]));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKekDeriver.SenderDerivation(new byte[31], new byte[1088]));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKekDeriver.SenderDerivation(new byte[32], null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKekDeriver.SenderDerivation(new byte[32], new byte[1087]));
        clear(returnedKek);
        clear(returnedCiphertext);
    }

    @Test
    void senderClearsSecretsCombinedInputAndTemporaryKek() {
        byte[] xSecret = filled(32, (byte) 0x11);
        MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(
                filled(1088, (byte) 0x22),
                filled(32, (byte) 0x33)
        );
        byte[] temporaryKek = filled(32, (byte) 0x44);
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(xSecret);
        RecordingMlKem768Crypto mlkem768 = RecordingMlKem768Crypto.forSender(encapsulation);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(temporaryKek, null);
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(x25519, mlkem768, hkdf);
        byte[] recipientXPublic = filled(32, (byte) 0x55);
        byte[] recipientPqPublic = filled(1184, (byte) 0x66);
        byte[] originalXPublic = recipientXPublic.clone();
        byte[] originalPqPublic = recipientPqPublic.clone();

        try (PublicHybridKekDeriver.SenderDerivation result = deriver.deriveForSender(
                DUMMY_X_HANDLE,
                recipientXPublic,
                recipientPqPublic
        )) {
            assertArrayEquals(filled(32, (byte) 0x44), result.kek());
            assertArrayEquals(filled(1088, (byte) 0x22), result.encapsulationCiphertext());
            assertTrue(allZero(xSecret));
            assertTrue(allZero(temporaryKek));
            assertTrue(allZero(encapsulation.sharedSecret()));
            assertTrue(allZero(hkdf.ikm));
            assertArrayEquals("wind".getBytes(StandardCharsets.UTF_8), hkdf.salt);
            assertArrayEquals(
                    "WindLetter v1 KEK | X25519ML-KEM-768".getBytes(StandardCharsets.UTF_8),
                    hkdf.info
            );
            assertEquals(32, hkdf.length);
            assertNotSame(recipientXPublic, x25519.peerPublicKey);
            assertNotSame(recipientPqPublic, mlkem768.encapsulationPublicKey);
            assertArrayEquals(originalXPublic, recipientXPublic);
            assertArrayEquals(originalPqPublic, recipientPqPublic);
        } finally {
            clear(recipientXPublic);
            clear(recipientPqPublic);
            clear(originalXPublic);
            clear(originalPqPublic);
        }
    }

    @Test
    void receiverClearsBothSecretsAndCombinedInputButReturnsOwnedKek() {
        byte[] xSecret = filled(32, (byte) 0x11);
        byte[] pqSecret = filled(32, (byte) 0x22);
        byte[] receiverKek = filled(32, (byte) 0x33);
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(xSecret);
        RecordingMlKem768Crypto mlkem768 = RecordingMlKem768Crypto.forReceiver(pqSecret);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(receiverKek, null);
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(x25519, mlkem768, hkdf);
        byte[] senderPublic = filled(32, (byte) 0x44);
        byte[] ciphertext = filled(1088, (byte) 0x55);
        byte[] originalSenderPublic = senderPublic.clone();
        byte[] originalCiphertext = ciphertext.clone();

        byte[] actual = deriver.deriveForReceiver(
                DUMMY_X_HANDLE,
                senderPublic,
                DUMMY_PQ_HANDLE,
                ciphertext
        );
        try {
            assertSame(receiverKek, actual);
            assertArrayEquals(filled(32, (byte) 0x33), actual);
            assertTrue(allZero(xSecret));
            assertTrue(allZero(pqSecret));
            assertTrue(allZero(hkdf.ikm));
            assertNotSame(senderPublic, x25519.peerPublicKey);
            assertNotSame(ciphertext, mlkem768.decapsulationCiphertext);
            assertArrayEquals(originalSenderPublic, senderPublic);
            assertArrayEquals(originalCiphertext, ciphertext);
        } finally {
            clear(actual);
            clear(senderPublic);
            clear(ciphertext);
            clear(originalSenderPublic);
            clear(originalCiphertext);
        }
    }

    @Test
    void validatesDependenciesAndInputsBeforeCrypto() {
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(filled(32, (byte) 1));
        MLKem768Encapsulation unusedEncapsulation =
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 2));
        RecordingMlKem768Crypto mlkem768 =
                RecordingMlKem768Crypto.forSender(unusedEncapsulation);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(filled(32, (byte) 3), null);
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(x25519, mlkem768, hkdf);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridKekDeriver(null, mlkem768, hkdf));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridKekDeriver(x25519, null, hkdf));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridKekDeriver(x25519, mlkem768, null));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForSender(null, new byte[32], new byte[1184]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForSender(DUMMY_X_HANDLE, null, new byte[1184]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForSender(DUMMY_X_HANDLE, new byte[31], new byte[1184]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForSender(DUMMY_X_HANDLE, new byte[32], null));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForSender(DUMMY_X_HANDLE, new byte[32], new byte[1183]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForReceiver(null, new byte[32], DUMMY_PQ_HANDLE, new byte[1088]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForReceiver(DUMMY_X_HANDLE, new byte[33], DUMMY_PQ_HANDLE, new byte[1088]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForReceiver(DUMMY_X_HANDLE, new byte[32], null, new byte[1088]));
            assertThrows(IllegalArgumentException.class,
                    () -> deriver.deriveForReceiver(DUMMY_X_HANDLE, new byte[32], DUMMY_PQ_HANDLE, new byte[1087]));
            assertEquals(0, x25519.calls);
            assertEquals(0, mlkem768.encapsulationCalls + mlkem768.decapsulationCalls);
            assertEquals(0, hkdf.calls);

            assertThrows(IllegalArgumentException.class,
                    () -> PublicHybridKekDeriver.deriveCombined(null, new byte[32], new byte[32]));
            assertThrows(IllegalArgumentException.class,
                    () -> PublicHybridKekDeriver.deriveCombined(hkdf, null, new byte[32]));
            assertThrows(IllegalArgumentException.class,
                    () -> PublicHybridKekDeriver.deriveCombined(hkdf, new byte[31], new byte[32]));
            assertThrows(IllegalArgumentException.class,
                    () -> PublicHybridKekDeriver.deriveCombined(hkdf, new byte[32], new byte[33]));
            assertEquals(0, hkdf.calls);
        } finally {
            unusedEncapsulation.close();
        }
    }

    @Test
    void rejectsMalformedOrZeroProviderSecretsAndClearsThem() {
        byte[] malformedXSecret = new byte[31];
        MLKem768Encapsulation unusedEncapsulation =
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 1));
        RecordingMlKem768Crypto mlkem768 =
                RecordingMlKem768Crypto.forSender(unusedEncapsulation);
        try {
            PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                    new RecordingX25519Crypto(malformedXSecret),
                    mlkem768,
                    new RecordingHkdfCrypto(filled(32, (byte) 2), null)
            );
            assertThrows(IllegalStateException.class, () -> deriver.deriveForSender(
                    DUMMY_X_HANDLE, new byte[32], new byte[1184]
            ));
            assertTrue(allZero(malformedXSecret));
            assertEquals(0, mlkem768.encapsulationCalls);
        } finally {
            unusedEncapsulation.close();
        }

        byte[] zeroXSecret = new byte[32];
        MLKem768Encapsulation secondUnused =
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 1));
        RecordingMlKem768Crypto secondMlkem = RecordingMlKem768Crypto.forSender(secondUnused);
        try {
            PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                    new RecordingX25519Crypto(zeroXSecret),
                    secondMlkem,
                    new RecordingHkdfCrypto(filled(32, (byte) 2), null)
            );
            assertThrows(CryptoOperationException.class, () -> deriver.deriveForSender(
                    DUMMY_X_HANDLE, new byte[32], new byte[1184]
            ));
            assertTrue(allZero(zeroXSecret));
            assertEquals(0, secondMlkem.encapsulationCalls);
        } finally {
            secondUnused.close();
        }

        byte[] xSecret = filled(32, (byte) 3);
        byte[] badPqSecret = new byte[31];
        PublicHybridKekDeriver receiver = new PublicHybridKekDeriver(
                new RecordingX25519Crypto(xSecret),
                RecordingMlKem768Crypto.forReceiver(badPqSecret),
                new RecordingHkdfCrypto(filled(32, (byte) 4), null)
        );
        assertThrows(IllegalStateException.class, () -> receiver.deriveForReceiver(
                DUMMY_X_HANDLE, new byte[32], DUMMY_PQ_HANDLE, new byte[1088]
        ));
        assertTrue(allZero(xSecret));
        assertTrue(allZero(badPqSecret));
    }

    @Test
    void rejectsNullProviderOutputsAndClearsPreviouslyDerivedSecrets() {
        byte[] senderXSecret = filled(32, (byte) 0x11);
        PublicHybridKekDeriver sender = new PublicHybridKekDeriver(
                new RecordingX25519Crypto(senderXSecret),
                RecordingMlKem768Crypto.forSender(null),
                new RecordingHkdfCrypto(filled(32, (byte) 0x22), null)
        );
        assertThrows(IllegalStateException.class, () -> sender.deriveForSender(
                DUMMY_X_HANDLE, new byte[32], new byte[1184]
        ));
        assertTrue(allZero(senderXSecret));

        byte[] receiverXSecret = filled(32, (byte) 0x33);
        PublicHybridKekDeriver receiver = new PublicHybridKekDeriver(
                new RecordingX25519Crypto(receiverXSecret),
                RecordingMlKem768Crypto.forReceiver(null),
                new RecordingHkdfCrypto(filled(32, (byte) 0x44), null)
        );
        assertThrows(IllegalStateException.class, () -> receiver.deriveForReceiver(
                DUMMY_X_HANDLE, new byte[32], DUMMY_PQ_HANDLE, new byte[1088]
        ));
        assertTrue(allZero(receiverXSecret));
    }

    @Test
    void rejectsHkdfContractFailuresClearsOutputsAndPreservesCause() {
        byte[] malformedKek = filled(31, (byte) 0x51);
        assertThrows(IllegalStateException.class, () -> PublicHybridKekDeriver.deriveCombined(
                new RecordingHkdfCrypto(malformedKek, null),
                filled(32, (byte) 1),
                filled(32, (byte) 2)
        ));
        assertTrue(allZero(malformedKek));

        assertThrows(IllegalStateException.class, () -> PublicHybridKekDeriver.deriveCombined(
                new RecordingHkdfCrypto(null, null),
                filled(32, (byte) 1),
                filled(32, (byte) 2)
        ));

        CryptoOperationException failure = new CryptoOperationException("hkdf failed");
        RecordingHkdfCrypto failing = new RecordingHkdfCrypto(null, failure);
        IllegalStateException wrapped = assertThrows(
                IllegalStateException.class,
                () -> PublicHybridKekDeriver.deriveCombined(
                        failing,
                        filled(32, (byte) 1),
                        filled(32, (byte) 2)
                )
        );
        assertEquals("HKDF provider failed", wrapped.getMessage());
        assertSame(failure, wrapped.getCause());
        assertTrue(allZero(failing.ikm));
    }

    private static final X25519PrivateKeyHandle DUMMY_X_HANDLE = new X25519PrivateKeyHandle() {
        @Override
        public byte[] publicKey() {
            return new byte[32];
        }

        @Override
        public void close() {
        }
    };

    private static final MLKem768PrivateKeyHandle DUMMY_PQ_HANDLE = new MLKem768PrivateKeyHandle() {
        @Override
        public byte[] publicKey() {
            return new byte[1184];
        }

        @Override
        public void close() {
        }
    };

    private static byte[] sequence(int start, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static boolean allZero(byte[] value) {
        if (value == null) {
            return false;
        }
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static final class RecordingX25519Crypto implements X25519Crypto {
        private final byte[] sharedSecret;
        private int calls;
        private byte[] peerPublicKey;

        private RecordingX25519Crypto(byte[] sharedSecret) {
            this.sharedSecret = sharedSecret;
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
            this.peerPublicKey = peerPublicKey;
            return sharedSecret;
        }
    }

    private static final class RecordingMlKem768Crypto implements MLKem768Crypto {
        private final MLKem768Encapsulation encapsulation;
        private final byte[] decapsulatedSecret;
        private int encapsulationCalls;
        private int decapsulationCalls;
        private byte[] encapsulationPublicKey;
        private byte[] decapsulationCiphertext;

        private RecordingMlKem768Crypto(
                MLKem768Encapsulation encapsulation,
                byte[] decapsulatedSecret
        ) {
            this.encapsulation = encapsulation;
            this.decapsulatedSecret = decapsulatedSecret;
        }

        private static RecordingMlKem768Crypto forSender(MLKem768Encapsulation encapsulation) {
            return new RecordingMlKem768Crypto(encapsulation, null);
        }

        private static RecordingMlKem768Crypto forReceiver(byte[] decapsulatedSecret) {
            return new RecordingMlKem768Crypto(null, decapsulatedSecret);
        }

        @Override
        public MLKem768PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MLKem768Encapsulation encapsulate(byte[] publicKey) {
            encapsulationCalls++;
            encapsulationPublicKey = publicKey;
            return encapsulation;
        }

        @Override
        public byte[] decapsulate(MLKem768PrivateKeyHandle privateKey, byte[] ciphertext) {
            decapsulationCalls++;
            decapsulationCiphertext = ciphertext;
            return decapsulatedSecret;
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
