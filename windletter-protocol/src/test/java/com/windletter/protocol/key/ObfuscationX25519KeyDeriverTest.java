package com.windletter.protocol.key;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObfuscationX25519KeyDeriverTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] ALICE_PRIVATE = HEX.parseHex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    );
    private static final byte[] BOB_PUBLIC = HEX.parseHex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    private static final byte[] EXPECTED_RID = HEX.parseHex(
            "31960c71ff806835cb242176264ebd4b"
    );
    private static final byte[] EXPECTED_KEK = HEX.parseHex(
            "277479809bf70197fc456c17b12429319823906852875eb2353482fb3a4e0cb6"
    );

    @Test
    void derivesRfc7748RidAndKekFixedVector() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                x25519,
                new BouncyCastleHkdfCrypto()
        );

        try (X25519PrivateKeyHandle alice = x25519.importPrivateKey(ALICE_PRIVATE);
             ObfuscationX25519KeyDeriver.DerivedMaterial material =
                     deriver.derive(alice, BOB_PUBLIC)) {
            byte[] rid = material.rid();
            byte[] kek = material.kek();
            try {
                assertArrayEquals(EXPECTED_RID, rid);
                assertArrayEquals(EXPECTED_KEK, kek);
            } finally {
                clear(rid);
                clear(kek);
            }
        }
    }

    @Test
    void derivesSameMaterialOnBothRealSidesWithoutClosingBorrowedHandles() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                x25519,
                new BouncyCastleHkdfCrypto()
        );

        try (X25519PrivateKeyHandle alice = x25519.generatePrivateKey();
             X25519PrivateKeyHandle bob = x25519.generatePrivateKey()) {
            byte[] alicePublic = alice.publicKey();
            byte[] bobPublic = bob.publicKey();
            try (ObfuscationX25519KeyDeriver.DerivedMaterial sender =
                         deriver.derive(alice, bobPublic);
                 ObfuscationX25519KeyDeriver.DerivedMaterial receiver =
                         deriver.derive(bob, alicePublic)) {
                byte[] senderRid = sender.rid();
                byte[] senderKek = sender.kek();
                byte[] receiverRid = receiver.rid();
                byte[] receiverKek = receiver.kek();
                try {
                    assertArrayEquals(senderRid, receiverRid);
                    assertArrayEquals(senderKek, receiverKek);
                    assertFalse(allZero(senderRid));
                    assertFalse(allZero(senderKek));
                } finally {
                    clear(senderRid);
                    clear(senderKek);
                    clear(receiverRid);
                    clear(receiverKek);
                }
            }

            assertArrayEquals(alicePublic, alice.publicKey());
            assertArrayEquals(bobPublic, bob.publicKey());
            clear(alicePublic);
            clear(bobPublic);
        }
    }

    @Test
    void callsOneX25519ThenTwoHkdfsWithExactContextsAndOneSharedReference() {
        List<String> order = new ArrayList<>();
        byte[] peerPublicKey = filled(32, (byte) 0x21);
        byte[] originalPeerPublicKey = peerPublicKey.clone();
        byte[] shared = filled(32, (byte) 0x32);
        byte[] ridProviderOutput = filled(16, (byte) 0x43);
        byte[] kekProviderOutput = filled(32, (byte) 0x54);
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(
                shared,
                null,
                order,
                true
        );
        ScriptedHkdfCrypto hkdf = ScriptedHkdfCrypto.recording(
                order,
                true,
                ridProviderOutput,
                kekProviderOutput
        );
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(x25519, hkdf);

        try (ObfuscationX25519KeyDeriver.DerivedMaterial ignored =
                     deriver.derive(new TrackingHandle(), peerPublicKey)) {
            assertEquals(List.of("x25519", "hkdf:16", "hkdf:32"), order);
            assertEquals(1, x25519.calls);
            assertEquals(2, hkdf.calls.size());
            assertNotSame(peerPublicKey, x25519.peerArgument);
            assertArrayEquals(originalPeerPublicKey, x25519.peerSnapshot);
            assertArrayEquals(originalPeerPublicKey, peerPublicKey);

            HkdfCall ridCall = hkdf.calls.get(0);
            HkdfCall kekCall = hkdf.calls.get(1);
            assertArrayEquals("wind".getBytes(StandardCharsets.UTF_8), ridCall.saltSnapshot());
            assertArrayEquals("rid/ecc".getBytes(StandardCharsets.UTF_8), ridCall.infoSnapshot());
            assertEquals(16, ridCall.length());
            assertArrayEquals("wind".getBytes(StandardCharsets.UTF_8), kekCall.saltSnapshot());
            assertArrayEquals(
                    "WindLetter v1 KEK | X25519".getBytes(StandardCharsets.UTF_8),
                    kekCall.infoSnapshot()
            );
            assertEquals(32, kekCall.length());
            assertSame(shared, ridCall.ikm());
            assertSame(shared, kekCall.ikm());
            assertNotSame(ridCall.saltArgument(), kekCall.saltArgument());
            assertNotSame(ridCall.infoArgument(), kekCall.infoArgument());
        }

        assertTrue(allZero(shared));
        assertTrue(allZero(ridProviderOutput));
        assertTrue(allZero(kekProviderOutput));
    }

    @Test
    void copiesMaterialBeforeClearingSuccessfulProviderOutputs() {
        byte[] shared = filled(32, (byte) 0x11);
        byte[] ridProviderOutput = filled(16, (byte) 0x22);
        byte[] kekProviderOutput = filled(32, (byte) 0x33);
        byte[] expectedRid = ridProviderOutput.clone();
        byte[] expectedKek = kekProviderOutput.clone();
        TrackingHandle ownKey = new TrackingHandle();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(shared),
                new ScriptedHkdfCrypto(ridProviderOutput, kekProviderOutput)
        );

        try (ObfuscationX25519KeyDeriver.DerivedMaterial material =
                     deriver.derive(ownKey, filled(32, (byte) 0x44))) {
            assertTrue(allZero(shared));
            assertTrue(allZero(ridProviderOutput));
            assertTrue(allZero(kekProviderOutput));

            Arrays.fill(ridProviderOutput, (byte) 0x55);
            Arrays.fill(kekProviderOutput, (byte) 0x66);
            byte[] rid = material.rid();
            byte[] kek = material.kek();
            try {
                assertArrayEquals(expectedRid, rid);
                assertArrayEquals(expectedKek, kek);
            } finally {
                clear(rid);
                clear(kek);
            }
        }

        assertEquals(0, ownKey.closeCalls);
        clear(expectedRid);
        clear(expectedKek);
        clear(ridProviderOutput);
        clear(kekProviderOutput);
    }

    @Test
    void validatesDependenciesAndInputsBeforeAnyCrypto() {
        RecordingX25519Crypto x25519 = new RecordingX25519Crypto(filled(32, (byte) 1));
        ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto(
                filled(16, (byte) 2),
                filled(32, (byte) 3)
        );
        TrackingHandle ownKey = new TrackingHandle();

        assertThrows(
                IllegalArgumentException.class,
                () -> new ObfuscationX25519KeyDeriver(null, hkdf)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ObfuscationX25519KeyDeriver(x25519, null)
        );

        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(x25519, hkdf);
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(null, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(ownKey, null));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(ownKey, new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> deriver.derive(ownKey, new byte[33]));

        assertEquals(0, x25519.calls);
        assertEquals(0, hkdf.calls.size());
        assertEquals(0, ownKey.closeCalls);
    }

    @Test
    void preservesX25519ProviderExceptionInstancesAndCategories() {
        TrackingHandle ownKey = new TrackingHandle();
        byte[] peerPublicKey = filled(32, (byte) 0x31);

        CryptoOperationException cryptoFailure =
                new CryptoOperationException("agreement failed");
        ScriptedHkdfCrypto cryptoHkdf = new ScriptedHkdfCrypto();
        ObfuscationX25519KeyDeriver cryptoDeriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(null, cryptoFailure, null, false),
                cryptoHkdf
        );
        assertSame(cryptoFailure, assertThrows(
                CryptoOperationException.class,
                () -> cryptoDeriver.derive(ownKey, peerPublicKey)
        ));
        assertEquals(0, cryptoHkdf.calls.size());

        IllegalStateException stateFailure = new IllegalStateException("closed handle");
        ScriptedHkdfCrypto stateHkdf = new ScriptedHkdfCrypto();
        ObfuscationX25519KeyDeriver stateDeriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(null, stateFailure, null, false),
                stateHkdf
        );
        assertSame(stateFailure, assertThrows(
                IllegalStateException.class,
                () -> stateDeriver.derive(ownKey, peerPublicKey)
        ));
        assertEquals(0, stateHkdf.calls.size());

        IllegalArgumentException argumentFailure = new IllegalArgumentException("foreign handle");
        ScriptedHkdfCrypto argumentHkdf = new ScriptedHkdfCrypto();
        ObfuscationX25519KeyDeriver argumentDeriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(null, argumentFailure, null, false),
                argumentHkdf
        );
        assertSame(argumentFailure, assertThrows(
                IllegalArgumentException.class,
                () -> argumentDeriver.derive(ownKey, peerPublicKey)
        ));
        assertEquals(0, argumentHkdf.calls.size());
        assertEquals(0, ownKey.closeCalls);
    }

    @Test
    void preservesRealClosedAndForeignHandleFailureCategories() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                x25519,
                new BouncyCastleHkdfCrypto()
        );
        X25519PrivateKeyHandle ownKey = x25519.generatePrivateKey();
        X25519PrivateKeyHandle peer = x25519.generatePrivateKey();
        try {
            byte[] peerPublicKey = peer.publicKey();
            ownKey.close();
            assertThrows(
                    IllegalStateException.class,
                    () -> deriver.derive(ownKey, peerPublicKey)
            );
            assertThrows(
                    IllegalArgumentException.class,
                    () -> deriver.derive(new TrackingHandle(), peerPublicKey)
            );
            clear(peerPublicKey);
        } finally {
            ownKey.close();
            peer.close();
        }
    }

    @Test
    void rejectsNullSharedSecretBeforeHkdf() {
        ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto();
        TrackingHandle ownKey = new TrackingHandle();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto((byte[]) null),
                hkdf
        );

        assertThrows(
                IllegalStateException.class,
                () -> deriver.derive(ownKey, filled(32, (byte) 0x41))
        );
        assertEquals(0, hkdf.calls.size());
        assertEquals(0, ownKey.closeCalls);
    }

    @Test
    void rejectsAndClearsWrongLengthSharedSecretsBeforeHkdf() {
        for (int length : new int[]{31, 33}) {
            byte[] malformedShared = filled(length, (byte) 0x51);
            ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto();
            ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                    new RecordingX25519Crypto(malformedShared),
                    hkdf
            );

            assertThrows(
                    IllegalStateException.class,
                    () -> deriver.derive(new TrackingHandle(), filled(32, (byte) 0x52))
            );
            assertTrue(allZero(malformedShared));
            assertEquals(0, hkdf.calls.size());
        }
    }

    @Test
    void rejectsAllZeroSharedSecretAsCryptoOperationFailureBeforeHkdf() {
        byte[] zeroShared = new byte[32];
        ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto();
        TrackingHandle ownKey = new TrackingHandle();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(zeroShared),
                hkdf
        );

        assertThrows(
                CryptoOperationException.class,
                () -> deriver.derive(ownKey, filled(32, (byte) 0x61))
        );
        assertTrue(allZero(zeroShared));
        assertEquals(0, hkdf.calls.size());
        assertEquals(0, ownKey.closeCalls);
    }

    @Test
    void wrapsRidHkdfCryptoFailureAndClearsSharedSecret() {
        byte[] shared = filled(32, (byte) 0x71);
        CryptoOperationException failure = new CryptoOperationException("rid hkdf failed");
        ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto(failure);
        TrackingHandle ownKey = new TrackingHandle();
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(shared),
                hkdf
        );

        IllegalStateException wrapper = assertThrows(
                IllegalStateException.class,
                () -> deriver.derive(ownKey, filled(32, (byte) 0x72))
        );
        assertEquals("HKDF provider failed", wrapper.getMessage());
        assertSame(failure, wrapper.getCause());
        assertEquals(1, hkdf.calls.size());
        assertTrue(allZero(shared));
        assertEquals(0, ownKey.closeCalls);
    }

    @Test
    void wrapsKekHkdfCryptoFailureAndClearsSharedAndRidOutputs() {
        byte[] shared = filled(32, (byte) 0x01);
        byte[] ridProviderOutput = filled(16, (byte) 0x02);
        CryptoOperationException failure = new CryptoOperationException("kek hkdf failed");
        ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto(ridProviderOutput, failure);
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                new RecordingX25519Crypto(shared),
                hkdf
        );

        IllegalStateException wrapper = assertThrows(
                IllegalStateException.class,
                () -> deriver.derive(new TrackingHandle(), filled(32, (byte) 0x03))
        );
        assertEquals("HKDF provider failed", wrapper.getMessage());
        assertSame(failure, wrapper.getCause());
        assertEquals(2, hkdf.calls.size());
        assertTrue(allZero(shared));
        assertTrue(allZero(ridProviderOutput));
    }

    @Test
    void rejectsNullOrWrongLengthRidOutputsAndClearsEveryNonNullOutput() {
        for (byte[] malformedRid : Arrays.asList(
                null,
                filled(15, (byte) 0x11),
                filled(17, (byte) 0x12)
        )) {
            byte[] shared = filled(32, (byte) 0x13);
            ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto(
                    new Object[]{malformedRid}
            );
            ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                    new RecordingX25519Crypto(shared),
                    hkdf
            );

            assertThrows(
                    IllegalStateException.class,
                    () -> deriver.derive(new TrackingHandle(), filled(32, (byte) 0x14))
            );
            assertEquals(1, hkdf.calls.size());
            assertTrue(allZero(shared));
            if (malformedRid != null) {
                assertTrue(allZero(malformedRid));
            }
        }
    }

    @Test
    void rejectsNullOrWrongLengthKekOutputsAndClearsRidAndKekOutputs() {
        for (byte[] malformedKek : Arrays.asList(
                null,
                filled(31, (byte) 0x21),
                filled(33, (byte) 0x22)
        )) {
            byte[] shared = filled(32, (byte) 0x23);
            byte[] ridProviderOutput = filled(16, (byte) 0x24);
            ScriptedHkdfCrypto hkdf = new ScriptedHkdfCrypto(
                    new Object[]{ridProviderOutput, malformedKek}
            );
            ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(
                    new RecordingX25519Crypto(shared),
                    hkdf
            );

            assertThrows(
                    IllegalStateException.class,
                    () -> deriver.derive(new TrackingHandle(), filled(32, (byte) 0x25))
            );
            assertEquals(2, hkdf.calls.size());
            assertTrue(allZero(shared));
            assertTrue(allZero(ridProviderOutput));
            if (malformedKek != null) {
                assertTrue(allZero(malformedKek));
            }
        }
    }

    @Test
    void derivedMaterialCopiesConstructionInputsAndEachAccessorResult() throws Exception {
        byte[] ridInput = filled(16, (byte) 0x31);
        byte[] kekInput = filled(32, (byte) 0x32);
        byte[] expectedRid = ridInput.clone();
        byte[] expectedKek = kekInput.clone();
        ObfuscationX25519KeyDeriver.DerivedMaterial material =
                newDerivedMaterial(ridInput, kekInput);
        try {
            Arrays.fill(ridInput, (byte) 0x41);
            Arrays.fill(kekInput, (byte) 0x42);

            byte[] firstRid = material.rid();
            byte[] secondRid = material.rid();
            byte[] firstKek = material.kek();
            byte[] secondKek = material.kek();
            try {
                assertNotSame(firstRid, secondRid);
                assertNotSame(firstKek, secondKek);
                assertArrayEquals(expectedRid, firstRid);
                assertArrayEquals(expectedRid, secondRid);
                assertArrayEquals(expectedKek, firstKek);
                assertArrayEquals(expectedKek, secondKek);

                Arrays.fill(firstRid, (byte) 0x51);
                Arrays.fill(firstKek, (byte) 0x52);
                assertArrayEquals(expectedRid, material.rid());
                assertArrayEquals(expectedKek, material.kek());
            } finally {
                clear(firstRid);
                clear(secondRid);
                clear(firstKek);
                clear(secondKek);
            }
        } finally {
            material.close();
            clear(ridInput);
            clear(kekInput);
            clear(expectedRid);
            clear(expectedKek);
        }
    }

    @Test
    void closeIsIdempotentClearsInternalMaterialAndDisablesAccessors() throws Exception {
        byte[] ridInput = filled(16, (byte) 0x61);
        byte[] kekInput = filled(32, (byte) 0x62);
        ObfuscationX25519KeyDeriver.DerivedMaterial material =
                newDerivedMaterial(ridInput, kekInput);
        byte[] internalRid = internalArray(material, "rid");
        byte[] internalKek = internalArray(material, "kek");
        assertNotSame(ridInput, internalRid);
        assertNotSame(kekInput, internalKek);
        assertFalse(allZero(internalRid));
        assertFalse(allZero(internalKek));

        material.close();
        assertTrue(allZero(internalRid));
        assertTrue(allZero(internalKek));
        material.close();
        assertTrue(allZero(internalRid));
        assertTrue(allZero(internalKek));
        assertThrows(IllegalStateException.class, material::rid);
        assertThrows(IllegalStateException.class, material::kek);
        clear(ridInput);
        clear(kekInput);
    }

    private static ObfuscationX25519KeyDeriver.DerivedMaterial newDerivedMaterial(
            byte[] rid,
            byte[] kek
    ) throws Exception {
        Constructor<ObfuscationX25519KeyDeriver.DerivedMaterial> constructor =
                ObfuscationX25519KeyDeriver.DerivedMaterial.class.getDeclaredConstructor(
                        byte[].class,
                        byte[].class
                );
        constructor.setAccessible(true);
        return constructor.newInstance(rid, kek);
    }

    private static byte[] internalArray(
            ObfuscationX25519KeyDeriver.DerivedMaterial material,
            String fieldName
    ) throws Exception {
        Field field = ObfuscationX25519KeyDeriver.DerivedMaterial.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (byte[]) field.get(material);
    }

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

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static final class TrackingHandle implements X25519PrivateKeyHandle {
        private int closeCalls;

        @Override
        public byte[] publicKey() {
            return new byte[32];
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class RecordingX25519Crypto implements X25519Crypto {
        private final byte[] shared;
        private final RuntimeException failure;
        private final List<String> order;
        private final boolean overwritePeer;
        private int calls;
        private byte[] peerArgument;
        private byte[] peerSnapshot;

        private RecordingX25519Crypto(byte[] shared) {
            this(shared, null, null, false);
        }

        private RecordingX25519Crypto(
                byte[] shared,
                RuntimeException failure,
                List<String> order,
                boolean overwritePeer
        ) {
            this.shared = shared;
            this.failure = failure;
            this.order = order;
            this.overwritePeer = overwritePeer;
        }

        @Override
        public X25519PrivateKeyHandle generatePrivateKey() {
            throw new AssertionError("generatePrivateKey must not be called");
        }

        @Override
        public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new AssertionError("importPrivateKey must not be called");
        }

        @Override
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey,
                byte[] peerPublicKey
        ) {
            calls++;
            if (order != null) {
                order.add("x25519");
            }
            peerArgument = peerPublicKey;
            peerSnapshot = peerPublicKey == null ? null : peerPublicKey.clone();
            if (overwritePeer && peerPublicKey != null) {
                Arrays.fill(peerPublicKey, (byte) 0x7f);
            }
            if (failure != null) {
                throw failure;
            }
            return shared;
        }
    }

    private static final class ScriptedHkdfCrypto implements HkdfCrypto {
        private final Object[] outcomes;
        private final List<String> order;
        private final boolean overwriteContext;
        private final List<HkdfCall> calls = new ArrayList<>();

        private ScriptedHkdfCrypto(Object... outcomes) {
            this(outcomes, null, false);
        }

        private ScriptedHkdfCrypto(
                Object[] outcomes,
                List<String> order,
                boolean overwriteContext
        ) {
            this.outcomes = outcomes;
            this.order = order;
            this.overwriteContext = overwriteContext;
        }

        private static ScriptedHkdfCrypto recording(
                List<String> order,
                boolean overwriteContext,
                Object... outcomes
        ) {
            return new ScriptedHkdfCrypto(outcomes, order, overwriteContext);
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            throw new AssertionError("extract must not be called");
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            throw new AssertionError("expand must not be called");
        }

        @Override
        public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
            int callIndex = calls.size();
            calls.add(new HkdfCall(
                    salt,
                    salt == null ? null : salt.clone(),
                    ikm,
                    info,
                    info == null ? null : info.clone(),
                    length
            ));
            if (order != null) {
                order.add("hkdf:" + length);
            }
            if (overwriteContext) {
                clear(salt);
                clear(info);
            }
            if (callIndex >= outcomes.length) {
                throw new AssertionError("unexpected HKDF call " + callIndex);
            }
            Object outcome = outcomes[callIndex];
            if (outcome instanceof RuntimeException failure) {
                throw failure;
            }
            return (byte[]) outcome;
        }
    }

    private record HkdfCall(
            byte[] saltArgument,
            byte[] saltSnapshot,
            byte[] ikm,
            byte[] infoArgument,
            byte[] infoSnapshot,
            int length
    ) {
    }
}
