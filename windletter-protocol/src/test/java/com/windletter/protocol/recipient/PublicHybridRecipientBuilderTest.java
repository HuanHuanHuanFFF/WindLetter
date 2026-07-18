package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridRecipientBuilderTest {

    private static final byte[] CEK = HexFormat.of().parseHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );

    @Test
    void buildsTwoRealHybridRecipientsThatEachUnwrapTheSameCek() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(deriver, keyWrap);
        byte[] cek = CEK.clone();

        try (X25519PrivateKeyHandle sender = x25519.generatePrivateKey();
             X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
             X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey()) {
            byte[] firstXPublic = firstX.publicKey();
            byte[] firstPqPublic = firstPq.publicKey();
            byte[] secondXPublic = secondX.publicKey();
            byte[] secondPqPublic = secondPq.publicKey();
            try {
                List<PublicRecipient> entries = builder.build(
                        sender,
                        List.of(
                                new PublicHybridRecipientKeys(firstXPublic, firstPqPublic),
                                new PublicHybridRecipientKeys(secondXPublic, secondPqPublic)
                        ),
                        cek
                );

                assertEquals(2, entries.size());
                assertEquals(X25519KeyId.derive(firstXPublic), entries.get(0).kid().x25519());
                assertEquals(MLKem768KeyId.derive(firstPqPublic), entries.get(0).kid().mlkem768());
                assertEquals(X25519KeyId.derive(secondXPublic), entries.get(1).kid().x25519());
                assertEquals(MLKem768KeyId.derive(secondPqPublic), entries.get(1).kid().mlkem768());
                assertEquals(1088, entries.get(0).ek().length);
                assertEquals(1088, entries.get(1).ek().length);
                assertEquals(40, entries.get(0).encryptedKey().length);
                assertEquals(40, entries.get(1).encryptedKey().length);
                assertFalse(Arrays.equals(entries.get(0).ek(), entries.get(1).ek()));

                X25519PrivateKeyHandle[] xHandles = {firstX, secondX};
                MLKem768PrivateKeyHandle[] pqHandles = {firstPq, secondPq};
                for (int i = 0; i < entries.size(); i++) {
                    byte[] senderPublic = sender.publicKey();
                    byte[] ek = entries.get(i).ek();
                    byte[] kek = null;
                    byte[] unwrapped = null;
                    try {
                        kek = deriver.deriveForReceiver(
                                xHandles[i], senderPublic, pqHandles[i], ek
                        );
                        unwrapped = keyWrap.unwrap(kek, entries.get(i).encryptedKey());
                        assertArrayEquals(cek, unwrapped);
                    } finally {
                        Arrays.fill(senderPublic, (byte) 0);
                        Arrays.fill(ek, (byte) 0);
                        if (kek != null) {
                            Arrays.fill(kek, (byte) 0);
                        }
                        if (unwrapped != null) {
                            Arrays.fill(unwrapped, (byte) 0);
                        }
                    }
                }
                assertArrayEquals(CEK, cek);
                assertEquals(32, sender.publicKey().length);
            } finally {
                Arrays.fill(firstXPublic, (byte) 0);
                Arrays.fill(firstPqPublic, (byte) 0);
                Arrays.fill(secondXPublic, (byte) 0);
                Arrays.fill(secondPqPublic, (byte) 0);
                Arrays.fill(cek, (byte) 0);
            }
        }
    }

    @Test
    void recipientKeysValidateAndDefensivelyCopyBothAlgorithms() {
        byte[] x25519 = filled(32, (byte) 0x11);
        byte[] mlkem768 = filled(1184, (byte) 0x22);
        byte[] expectedX25519 = x25519.clone();
        byte[] expectedMlkem768 = mlkem768.clone();

        PublicHybridRecipientKeys keys = new PublicHybridRecipientKeys(x25519, mlkem768);
        Arrays.fill(x25519, (byte) 0);
        Arrays.fill(mlkem768, (byte) 0);
        assertArrayEquals(expectedX25519, keys.x25519PublicKey());
        assertArrayEquals(expectedMlkem768, keys.mlkem768PublicKey());

        byte[] xAccessor = keys.x25519PublicKey();
        byte[] pqAccessor = keys.mlkem768PublicKey();
        Arrays.fill(xAccessor, (byte) 0);
        Arrays.fill(pqAccessor, (byte) 0);
        assertArrayEquals(expectedX25519, keys.x25519PublicKey());
        assertArrayEquals(expectedMlkem768, keys.mlkem768PublicKey());

        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(null, expectedMlkem768));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(new byte[31], expectedMlkem768));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(new byte[33], expectedMlkem768));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(expectedX25519, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(expectedX25519, new byte[1183]));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientKeys(expectedX25519, new byte[1185]));

        Arrays.fill(expectedX25519, (byte) 0);
        Arrays.fill(expectedMlkem768, (byte) 0);
    }

    @Test
    void validatesTheWholePairSetBeforeAnyAgreementEncapsulationOrWrap() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingMlKem768Crypto mlkem = new CountingMlKem768Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        TrackingKeyWrap keyWrap = TrackingKeyWrap.success();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(x25519, mlkem, hkdf);
        PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(deriver, keyWrap);
        PublicHybridRecipientKeys valid = keys(1, 1);
        PublicHybridRecipientKeys duplicate = keys(1, 1);

        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientBuilder(null, keyWrap));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientBuilder(deriver, null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(null, List.of(valid), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, null, CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, List.of(), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, uniquePairs(33), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(
                        DUMMY_X25519_HANDLE,
                        Arrays.asList(valid, (PublicHybridRecipientKeys) null),
                        CEK
                ));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, List.of(valid, duplicate), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, List.of(valid), null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, List.of(valid), new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_X25519_HANDLE, List.of(valid), new byte[33]));

        assertEquals(0, x25519.calls);
        assertEquals(0, mlkem.encapsulateCalls);
        assertEquals(0, hkdf.calls);
        assertEquals(0, keyWrap.calls);
    }

    @Test
    void acceptsSameSingleComponentWhenTheFullPairDiffers() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingMlKem768Crypto mlkem = new CountingMlKem768Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        TrackingKeyWrap keyWrap = TrackingKeyWrap.success();
        PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(
                new PublicHybridKekDeriver(x25519, mlkem, hkdf), keyWrap
        );
        PublicHybridRecipientKeys first = keys(7, 8);
        PublicHybridRecipientKeys sameX = keys(7, 9);
        PublicHybridRecipientKeys samePq = keys(10, 8);

        List<PublicRecipient> entries = builder.build(
                DUMMY_X25519_HANDLE, List.of(first, sameX, samePq), CEK
        );

        assertEquals(3, entries.size());
        assertEquals(entries.get(0).kid().x25519(), entries.get(1).kid().x25519());
        assertFalse(entries.get(0).kid().mlkem768().equals(entries.get(1).kid().mlkem768()));
        assertEquals(entries.get(0).kid().mlkem768(), entries.get(2).kid().mlkem768());
        assertFalse(entries.get(0).kid().x25519().equals(entries.get(2).kid().x25519()));
        assertEquals(3, x25519.calls);
        assertEquals(3, mlkem.encapsulateCalls);
        assertEquals(3, hkdf.calls);
        assertEquals(3, keyWrap.calls);
    }

    @Test
    void snapshotsAllPairsBeforeCryptoAndReturnsOrderedImmutableEntries() {
        ArrayList<PublicHybridRecipientKeys> callerPairs = new ArrayList<>();
        PublicHybridRecipientKeys first = keys(1, 11);
        PublicHybridRecipientKeys second = keys(2, 12);
        PublicHybridRecipientKeys replacement = keys(3, 13);
        callerPairs.add(first);
        callerPairs.add(second);
        String expectedSecondXKid = X25519KeyId.derive(second.x25519PublicKey());
        String expectedSecondPqKid = MLKem768KeyId.derive(second.mlkem768PublicKey());
        CountingX25519Crypto x25519 = new CountingX25519Crypto(
                () -> callerPairs.set(1, replacement)
        );
        TrackingKeyWrap keyWrap = TrackingKeyWrap.success();
        PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(
                new PublicHybridKekDeriver(
                        x25519, new CountingMlKem768Crypto(), new CountingHkdfCrypto()
                ),
                keyWrap
        );
        byte[] cek = CEK.clone();

        List<PublicRecipient> entries = builder.build(DUMMY_X25519_HANDLE, callerPairs, cek);

        assertEquals(2, entries.size());
        assertEquals(X25519KeyId.derive(first.x25519PublicKey()), entries.get(0).kid().x25519());
        assertEquals(expectedSecondXKid, entries.get(1).kid().x25519());
        assertEquals(expectedSecondPqKid, entries.get(1).kid().mlkem768());
        assertArrayEquals(CEK, cek);
        assertThrows(UnsupportedOperationException.class, () -> entries.add(entries.get(0)));
        assertTrue(allZero(keyWrap.capturedKek));
        assertTrue(allZero(keyWrap.capturedCek));
        assertTrue(allZero(keyWrap.returnedOutput));
        assertFalse(allZero(entries.get(1).encryptedKey()));
        Arrays.fill(cek, (byte) 0);
    }

    @Test
    void acceptsExactly32PairsAndPreservesTheirOrder() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingMlKem768Crypto mlkem = new CountingMlKem768Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        TrackingKeyWrap keyWrap = TrackingKeyWrap.success();
        PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(
                new PublicHybridKekDeriver(x25519, mlkem, hkdf), keyWrap
        );
        List<PublicHybridRecipientKeys> pairs = uniquePairs(32);

        List<PublicRecipient> entries = builder.build(DUMMY_X25519_HANDLE, pairs, CEK);

        assertEquals(32, entries.size());
        assertEquals(32, x25519.calls);
        assertEquals(32, mlkem.encapsulateCalls);
        assertEquals(32, hkdf.calls);
        assertEquals(32, keyWrap.calls);
        for (int i = 0; i < entries.size(); i++) {
            assertEquals(
                    X25519KeyId.derive(pairs.get(i).x25519PublicKey()),
                    entries.get(i).kid().x25519()
            );
            assertEquals(
                    MLKem768KeyId.derive(pairs.get(i).mlkem768PublicKey()),
                    entries.get(i).kid().mlkem768()
            );
        }
    }

    @Test
    void wrapThrowNullAndWrongLengthClearKekCekAndReturnedSnapshots() {
        for (TrackingKeyWrap keyWrap : List.of(
                TrackingKeyWrap.throwing(),
                TrackingKeyWrap.nullOutput(),
                TrackingKeyWrap.wrongLength()
        )) {
            TrackingX25519Handle sender = new TrackingX25519Handle();
            PublicHybridRecipientBuilder builder = new PublicHybridRecipientBuilder(
                    new PublicHybridKekDeriver(
                            new CountingX25519Crypto(),
                            new CountingMlKem768Crypto(),
                            new CountingHkdfCrypto()
                    ),
                    keyWrap
            );
            byte[] cek = CEK.clone();

            RuntimeException failure = assertThrows(RuntimeException.class,
                    () -> builder.build(sender, List.of(keys(20, 21)), cek));
            if (keyWrap.failure == null) {
                assertTrue(failure instanceof IllegalStateException);
            } else {
                assertEquals(keyWrap.failure, failure);
            }
            assertTrue(allZero(keyWrap.capturedKek));
            assertTrue(allZero(keyWrap.capturedCek));
            if (keyWrap.returnedOutput != null) {
                assertTrue(allZero(keyWrap.returnedOutput));
            }
            assertArrayEquals(CEK, cek);
            assertFalse(sender.closed);
            assertEquals(32, sender.publicKey().length);
            Arrays.fill(cek, (byte) 0);
        }
    }

    private static final X25519PrivateKeyHandle DUMMY_X25519_HANDLE = new TrackingX25519Handle();

    private static PublicHybridRecipientKeys keys(int xMarker, int pqMarker) {
        byte[] x25519 = new byte[32];
        byte[] mlkem768 = new byte[1184];
        x25519[0] = (byte) xMarker;
        mlkem768[0] = (byte) pqMarker;
        return new PublicHybridRecipientKeys(x25519, mlkem768);
    }

    private static List<PublicHybridRecipientKeys> uniquePairs(int count) {
        List<PublicHybridRecipientKeys> pairs = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            pairs.add(keys(i + 1, 100 + i));
        }
        return pairs;
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
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static final class TrackingX25519Handle implements X25519PrivateKeyHandle {
        private boolean closed;

        @Override
        public byte[] publicKey() {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            return filled(32, (byte) 0x71);
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    private static final class CountingX25519Crypto implements X25519Crypto {
        private final Runnable firstCall;
        private int calls;

        private CountingX25519Crypto() {
            this(null);
        }

        private CountingX25519Crypto(Runnable firstCall) {
            this.firstCall = firstCall;
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
            if (calls == 1 && firstCall != null) {
                firstCall.run();
            }
            return filled(32, (byte) calls);
        }
    }

    private static final class CountingMlKem768Crypto implements MLKem768Crypto {
        private int encapsulateCalls;

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
            encapsulateCalls++;
            return new MLKem768Encapsulation(
                    filled(1088, (byte) encapsulateCalls),
                    filled(32, (byte) (0x40 + encapsulateCalls))
            );
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class CountingHkdfCrypto implements HkdfCrypto {
        private int calls;

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
            return filled(32, (byte) (0x20 + calls));
        }
    }

    private static final class TrackingKeyWrap implements A256KeyWrapCrypto {
        private final RuntimeException failure;
        private final int outputLength;
        private int calls;
        private byte[] capturedKek;
        private byte[] capturedCek;
        private byte[] returnedOutput;

        private TrackingKeyWrap(RuntimeException failure, int outputLength) {
            this.failure = failure;
            this.outputLength = outputLength;
        }

        private static TrackingKeyWrap success() {
            return new TrackingKeyWrap(null, 40);
        }

        private static TrackingKeyWrap throwing() {
            return new TrackingKeyWrap(new CryptoOperationException("wrap failed"), 40);
        }

        private static TrackingKeyWrap nullOutput() {
            return new TrackingKeyWrap(null, -1);
        }

        private static TrackingKeyWrap wrongLength() {
            return new TrackingKeyWrap(null, 39);
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            calls++;
            capturedKek = kek;
            capturedCek = keyToWrap;
            if (failure != null) {
                throw failure;
            }
            if (outputLength < 0) {
                return null;
            }
            returnedOutput = filled(outputLength, (byte) calls);
            return returnedOutput;
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new UnsupportedOperationException();
        }
    }
}
