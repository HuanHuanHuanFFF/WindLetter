package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
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
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObfuscationHybridRecipientBuilderTest {

    private static final byte[] CEK = sequence(32, 0);

    @Test
    void publicKeyPairValidatesLengthsAndOwnsDefensiveCopies() {
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(null, new byte[1184]));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(new byte[31], new byte[1184]));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(new byte[33], new byte[1184]));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(new byte[32], null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(new byte[32], new byte[1183]));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientKeys(new byte[32], new byte[1185]));

        byte[] x = filled(32, (byte) 0x11);
        byte[] pq = filled(1184, (byte) 0x22);
        ObfuscationHybridRecipientKeys keys = new ObfuscationHybridRecipientKeys(x, pq);
        clear(x);
        clear(pq);
        byte[] firstX = keys.x25519PublicKey();
        byte[] secondX = keys.x25519PublicKey();
        byte[] firstPq = keys.mlkem768PublicKey();
        byte[] secondPq = keys.mlkem768PublicKey();
        try {
            assertNotSame(firstX, secondX);
            assertNotSame(firstPq, secondPq);
            assertArrayEquals(filled(32, (byte) 0x11), secondX);
            assertArrayEquals(filled(1184, (byte) 0x22), secondPq);
            clear(firstX);
            clear(firstPq);
            assertArrayEquals(filled(32, (byte) 0x11), keys.x25519PublicKey());
            assertArrayEquals(filled(1184, (byte) 0x22), keys.mlkem768PublicKey());
        } finally {
            clear(firstX);
            clear(secondX);
            clear(firstPq);
            clear(secondPq);
        }
    }

    @Test
    void realBouncyCastleRecipientsShareOneEpkButUseIndependentKemEntries() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        ObfuscationHybridRecipientBuilder builder =
                new ObfuscationHybridRecipientBuilder(x25519, mlkem768, hkdf, keyWrap);
        ObfuscationHybridKeyDeriver deriver =
                new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);
        byte[] cek = CEK.clone();

        try (X25519PrivateKeyHandle x1 = x25519.generatePrivateKey();
             X25519PrivateKeyHandle x2 = x25519.generatePrivateKey();
             X25519PrivateKeyHandle x3 = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle pq1 = mlkem768.generatePrivateKey();
             MLKem768PrivateKeyHandle pq2 = mlkem768.generatePrivateKey();
             MLKem768PrivateKeyHandle pq3 = mlkem768.generatePrivateKey()) {
            List<X25519PrivateKeyHandle> xHandles = List.of(x1, x2, x3);
            List<MLKem768PrivateKeyHandle> pqHandles = List.of(pq1, pq2, pq3);
            List<ObfuscationHybridRecipientKeys> recipients = List.of(
                    new ObfuscationHybridRecipientKeys(x1.publicKey(), pq1.publicKey()),
                    new ObfuscationHybridRecipientKeys(x2.publicKey(), pq2.publicKey()),
                    new ObfuscationHybridRecipientKeys(x3.publicKey(), pq3.publicKey())
            );

            ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                    builder.build(recipients, cek);

            assertEquals(8, prepared.recipients().size());
            assertEquals("OKP", prepared.epk().kty());
            assertEquals("X25519", prepared.epk().crv());
            assertEquals(32, prepared.epk().x().length);
            assertHybridShapeAndUniqueRids(prepared.recipients());
            Set<String> realEks = new HashSet<>();

            for (int i = 0; i < xHandles.size(); i++) {
                int matches = 0;
                byte[] epkX = prepared.epk().x();
                try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                             deriver.openForReceiver(xHandles.get(i), pqHandles.get(i), epkX)) {
                    for (RecipientEntry entry : prepared.recipients()) {
                        ObfuscationRecipient recipient = (ObfuscationRecipient) entry;
                        byte[] ek = recipient.ek();
                        byte[] wireRid = recipient.rid();
                        try (ObfuscationHybridKeyDeriver.DerivedMaterial material =
                                     context.deriveEntry(ek)) {
                            byte[] derivedRid = material.rid();
                            try {
                                if (MessageDigest.isEqual(derivedRid, wireRid)) {
                                    byte[] kek = material.kek();
                                    byte[] encryptedKey = recipient.encryptedKey();
                                    byte[] unwrapped = null;
                                    try {
                                        unwrapped = keyWrap.unwrap(kek, encryptedKey);
                                        assertArrayEquals(cek, unwrapped);
                                        assertTrue(realEks.add(Base64.getEncoder().encodeToString(ek)));
                                        matches++;
                                    } finally {
                                        clear(kek);
                                        clear(encryptedKey);
                                        clear(unwrapped);
                                    }
                                }
                            } finally {
                                clear(derivedRid);
                            }
                        } finally {
                            clear(ek);
                            clear(wireRid);
                        }
                    }
                } finally {
                    clear(epkX);
                }
                assertEquals(1, matches);
            }
            assertEquals(3, realEks.size(), "each real recipient must own an independent ek");
        } finally {
            clear(cek);
        }
    }

    @ParameterizedTest
    @CsvSource({"1,8", "8,8", "9,16", "16,16", "17,32", "32,32"})
    void padsToExactBucketsWithOneEphemeralAndOneEncapsulationPerRealPair(
            int realCount,
            int expectedBucket
    ) {
        Fixture fixture = new Fixture();

        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(keyPairs(realCount), CEK);

        assertEquals(expectedBucket, prepared.recipients().size());
        assertHybridShapeAndUniqueRids(prepared.recipients());
        assertEquals(1, fixture.x25519.generateCalls);
        assertEquals(realCount, fixture.x25519.deriveCalls);
        assertEquals(realCount, fixture.mlkem768.encapsulationCalls);
        assertEquals(realCount * 2, fixture.hkdf.calls);
        assertEquals(realCount, fixture.keyWrap.calls);
        assertEquals(1, fixture.x25519.handles.get(0).closeCalls);
        assertEquals(realCount, new HashSet<>(fixture.mlkem768.ekFingerprints).size());
        fixture.keyWrap.assertSensitiveArgumentsCleared();
    }

    @Test
    void validatesEverythingBeforeCryptoAndRejectsOnlyExactPairDuplicates() {
        TrackingX25519Crypto x = new TrackingX25519Crypto(new ArrayList<>());
        TrackingMlKem768Crypto pq = new TrackingMlKem768Crypto(new ArrayList<>());
        TrackingHkdfCrypto hkdf = new TrackingHkdfCrypto(new ArrayList<>());
        TrackingKeyWrapCrypto wrap = new TrackingKeyWrapCrypto(new ArrayList<>());
        TrackingSecureRandom random = new TrackingSecureRandom(new ArrayList<>());
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder(null, pq, hkdf, wrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder(x, null, hkdf, wrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder(x, pq, null, wrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder(x, pq, hkdf, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder(x, pq, hkdf, wrap, null));

        List<List<ObfuscationHybridRecipientKeys>> invalidLists = List.of(
                List.of(),
                keyPairs(33),
                Arrays.asList((ObfuscationHybridRecipientKeys) null)
        );
        for (List<ObfuscationHybridRecipientKeys> invalid : invalidLists) {
            Fixture fixture = new Fixture();
            assertThrows(IllegalArgumentException.class,
                    () -> fixture.builder().build(invalid, CEK));
            fixture.assertUnused();
        }
        Fixture nullList = new Fixture();
        assertThrows(IllegalArgumentException.class,
                () -> nullList.builder().build(null, CEK));
        nullList.assertUnused();

        for (byte[] invalidCek : new byte[][]{null, new byte[31], new byte[33]}) {
            Fixture fixture = new Fixture();
            assertThrows(IllegalArgumentException.class,
                    () -> fixture.builder().build(keyPairs(1), invalidCek));
            fixture.assertUnused();
        }

        byte[] sameX = filled(32, (byte) 0x31);
        byte[] samePq = filled(1184, (byte) 0x32);
        Fixture duplicate = new Fixture();
        assertThrows(IllegalArgumentException.class, () -> duplicate.builder().build(
                List.of(
                        new ObfuscationHybridRecipientKeys(sameX, samePq),
                        new ObfuscationHybridRecipientKeys(sameX.clone(), samePq.clone())
                ),
                CEK
        ));
        duplicate.assertUnused();

        Fixture sharedComponent = new Fixture();
        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                sharedComponent.builder().build(List.of(
                        new ObfuscationHybridRecipientKeys(sameX, filled(1184, (byte) 0x41)),
                        new ObfuscationHybridRecipientKeys(sameX, filled(1184, (byte) 0x42)),
                        new ObfuscationHybridRecipientKeys(filled(32, (byte) 0x51), samePq),
                        new ObfuscationHybridRecipientKeys(filled(32, (byte) 0x52), samePq)
                ), CEK);
        assertEquals(8, prepared.recipients().size());
        assertEquals(4, sharedComponent.mlkem768.encapsulationCalls);
        clear(sameX);
        clear(samePq);
    }

    @Test
    void snapshotsInputsAndBuildsAllRealEntriesBeforeDecoysAndShuffle() {
        List<String> order = new ArrayList<>();
        Fixture fixture = new Fixture(order);
        byte[] cek = CEK.clone();
        byte[] expectedCek = cek.clone();
        List<ObfuscationHybridRecipientKeys> callerList = new ArrayList<>(keyPairs(2));
        fixture.x25519.onGenerate = () -> {
            clear(cek);
            callerList.clear();
        };

        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(callerList, cek);

        assertEquals(8, prepared.recipients().size());
        assertEquals(2, fixture.mlkem768.publicKeySnapshots.size());
        fixture.keyWrap.cekSnapshots.forEach(value -> assertArrayEquals(expectedCek, value));
        int firstRandom = firstIndexStartingWith(order, "random:");
        assertTrue(firstRandom > order.lastIndexOf("wrap"));
        assertTrue(order.lastIndexOf("encap") < firstRandom);
        assertEquals("close", order.get(order.size() - 1));
        assertTrue(order.contains("random:16"));
        assertTrue(order.contains("random:1088"));
        assertTrue(order.contains("random:40"));
        List<String> randomEvents = order.stream()
                .filter(value -> value.startsWith("random:"))
                .toList();
        List<String> expectedRandomEvents = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            expectedRandomEvents.add("random:16");
            expectedRandomEvents.add("random:1088");
            expectedRandomEvents.add("random:40");
        }
        assertEquals(expectedRandomEvents, randomEvents);

        Set<String> wireEks = new HashSet<>();
        Set<String> wireEncryptedKeys = new HashSet<>();
        for (RecipientEntry entry : prepared.recipients()) {
            ObfuscationRecipient recipient = (ObfuscationRecipient) entry;
            byte[] ek = recipient.ek();
            byte[] encryptedKey = recipient.encryptedKey();
            try {
                wireEks.add(Base64.getEncoder().encodeToString(ek));
                wireEncryptedKeys.add(Base64.getEncoder().encodeToString(encryptedKey));
            } finally {
                clear(ek);
                clear(encryptedKey);
            }
        }
        assertTrue(wireEks.containsAll(fixture.random.generatedEkFingerprints));
        assertTrue(wireEncryptedKeys.containsAll(
                fixture.random.generatedEncryptedKeyFingerprints
        ));
        fixture.keyWrap.assertSensitiveArgumentsCleared();
        clear(expectedCek);
    }

    @Test
    void enforcesGlobalRidUniquenessAndIndependent128AttemptLimit() {
        byte[] collision = filled(16, (byte) 0x61);
        Fixture realCollision = new Fixture();
        realCollision.hkdf.scriptRids(collision, collision);
        assertThrows(IllegalStateException.class,
                () -> realCollision.builder().build(keyPairs(2), CEK));
        assertEquals(0, realCollision.random.nextBytesCalls);
        assertEquals(1, realCollision.x25519.handles.get(0).closeCalls);

        Fixture resampling = new Fixture();
        byte[] firstDecoy = filled(16, (byte) 0x62);
        resampling.hkdf.scriptRids(collision);
        resampling.random.scriptRids(collision, firstDecoy, firstDecoy, filled(16, (byte) 0x63));
        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                resampling.builder().build(keyPairs(1), CEK);
        assertHybridShapeAndUniqueRids(prepared.recipients());
        assertEquals(9, resampling.random.ridCalls);

        Fixture independentBudgets = new Fixture();
        byte[] budgetRealRid = filled(16, (byte) 0x11);
        byte[] firstBudgetDecoy = filled(16, (byte) 0x22);
        byte[] secondBudgetDecoy = filled(16, (byte) 0x33);
        independentBudgets.hkdf.scriptRids(budgetRealRid);
        byte[][] scriptedAttempts = new byte[256][];
        for (int i = 0; i < 127; i++) {
            scriptedAttempts[i] = budgetRealRid;
        }
        scriptedAttempts[127] = firstBudgetDecoy;
        for (int i = 128; i < 255; i++) {
            scriptedAttempts[i] = firstBudgetDecoy;
        }
        scriptedAttempts[255] = secondBudgetDecoy;
        independentBudgets.random.scriptRids(scriptedAttempts);
        ObfuscationHybridRecipientBuilder.PreparedRecipients independentlyPrepared =
                independentBudgets.builder().build(keyPairs(1), CEK);
        assertHybridShapeAndUniqueRids(independentlyPrepared.recipients());
        assertEquals(
                261,
                independentBudgets.random.ridCalls,
                "each decoy must receive its own 128-attempt budget"
        );

        Fixture exhausted = new Fixture();
        exhausted.hkdf.scriptRids(collision);
        exhausted.random.repeatedRid = collision;
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> exhausted.builder().build(keyPairs(1), CEK));
        assertTrue(failure.getMessage().contains("128"));
        assertEquals(128, exhausted.random.ridCalls);
        assertEquals(0, exhausted.random.nextIntCalls);
        assertEquals(1, exhausted.x25519.handles.get(0).closeCalls);
        clear(collision);
        clear(firstDecoy);
        clear(budgetRealRid);
        clear(firstBudgetDecoy);
        clear(secondBudgetDecoy);
    }

    @Test
    void usesExactFisherYatesBoundsOverTheFinalList() {
        Fixture fixture = new Fixture();
        fixture.random.scriptNextInts(0, 0, 0, 0, 0, 0, 0);

        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(keyPairs(1), CEK);

        assertEquals(List.of(8, 7, 6, 5, 4, 3, 2), fixture.random.bounds);
        String realEk = fixture.mlkem768.ekFingerprints.get(0);
        int realIndex = -1;
        for (int i = 0; i < prepared.recipients().size(); i++) {
            byte[] ek = ((ObfuscationRecipient) prepared.recipients().get(i)).ek();
            try {
                if (realEk.equals(Base64.getEncoder().encodeToString(ek))) {
                    realIndex = i;
                }
            } finally {
                clear(ek);
            }
        }
        assertEquals(7, realIndex, "scripted Fisher-Yates must move the real entry");
    }

    @Test
    void closesEphemeralAndClearsSensitiveWrapArgumentsOnFailures() {
        Fixture encapsulationFailure = new Fixture();
        RuntimeException encapCause = new IllegalStateException("encap failed");
        encapsulationFailure.mlkem768.failure = encapCause;
        assertSame(encapCause, assertThrows(IllegalStateException.class,
                () -> encapsulationFailure.builder().build(keyPairs(1), CEK)));
        assertEquals(1, encapsulationFailure.x25519.handles.get(0).closeCalls);
        assertEquals(0, encapsulationFailure.keyWrap.calls);
        assertEquals(0, encapsulationFailure.random.nextBytesCalls);

        Fixture wrapFailure = new Fixture();
        RuntimeException wrapCause = new UnsupportedOperationException("wrap failed");
        wrapFailure.keyWrap.failure = wrapCause;
        IllegalStateException mapped = assertThrows(IllegalStateException.class,
                () -> wrapFailure.builder().build(keyPairs(1), CEK));
        assertSame(wrapCause, mapped.getCause());
        assertEquals(1, wrapFailure.x25519.handles.get(0).closeCalls);
        assertEquals(0, wrapFailure.random.nextBytesCalls);
        wrapFailure.keyWrap.assertSensitiveArgumentsCleared();

        Fixture randomFailure = new Fixture();
        randomFailure.random.failure = new IllegalStateException("random failed");
        assertThrows(IllegalStateException.class,
                () -> randomFailure.builder().build(keyPairs(1), CEK));
        assertEquals(1, randomFailure.x25519.handles.get(0).closeCalls);
        randomFailure.keyWrap.assertSensitiveArgumentsCleared();
    }

    @Test
    void preparedRecipientsRejectMalformedHybridShapeAndRemainImmutable() {
        Epk epk = new Epk("OKP", "X25519", filled(32, (byte) 0x11));
        List<RecipientEntry> valid = validEntries(8);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(null, valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(
                        new Epk("EC", "X25519", new byte[32]), valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(
                        new Epk("OKP", "X25519", new byte[31]), valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, validEntries(7)));

        List<RecipientEntry> wrongType = new ArrayList<>(valid);
        wrongType.set(0, new PublicRecipient(new RecipientKid("kid", null), new byte[40], null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, wrongType));
        assertPreparedRejects(epk, valid,
                new ObfuscationRecipient(new byte[15], new byte[40], new byte[1088]));
        assertPreparedRejects(epk, valid,
                new ObfuscationRecipient(new byte[16], new byte[39], new byte[1088]));
        assertPreparedRejects(epk, valid,
                new ObfuscationRecipient(new byte[16], new byte[40], null));
        assertPreparedRejects(epk, valid,
                new ObfuscationRecipient(new byte[16], new byte[40], new byte[1087]));
        assertPreparedRejects(epk, valid,
                new ObfuscationRecipient(new byte[16], new byte[40], new byte[1089]));

        List<RecipientEntry> duplicateRid = new ArrayList<>(valid);
        byte[] firstRid = ((ObfuscationRecipient) valid.get(0)).rid();
        duplicateRid.set(1, new ObfuscationRecipient(firstRid, new byte[40], new byte[1088]));
        clear(firstRid);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, duplicateRid));

        List<RecipientEntry> mutable = new ArrayList<>(valid);
        ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, mutable);
        mutable.clear();
        assertEquals(8, prepared.recipients().size());
        assertThrows(UnsupportedOperationException.class, () -> prepared.recipients().clear());
        assertHybridShapeAndUniqueRids(prepared.recipients());
    }

    private static void assertPreparedRejects(Epk epk, List<RecipientEntry> valid, RecipientEntry bad) {
        List<RecipientEntry> entries = new ArrayList<>(valid);
        entries.set(0, bad);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientBuilder.PreparedRecipients(epk, entries));
    }

    private static void assertHybridShapeAndUniqueRids(List<RecipientEntry> entries) {
        Set<String> rids = new HashSet<>();
        for (RecipientEntry entry : entries) {
            ObfuscationRecipient recipient = assertInstanceOf(ObfuscationRecipient.class, entry);
            byte[] rid = recipient.rid();
            byte[] encryptedKey = recipient.encryptedKey();
            byte[] ek = recipient.ek();
            try {
                assertEquals(16, rid.length);
                assertEquals(40, encryptedKey.length);
                assertEquals(1088, ek.length);
                assertTrue(rids.add(Base64.getEncoder().encodeToString(rid)));
            } finally {
                clear(rid);
                clear(encryptedKey);
                clear(ek);
            }
        }
    }

    private static List<ObfuscationHybridRecipientKeys> keyPairs(int count) {
        List<ObfuscationHybridRecipientKeys> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] x = new byte[32];
            byte[] pq = new byte[1184];
            x[0] = (byte) (i + 1);
            x[31] = (byte) (0x80 + i);
            pq[0] = (byte) (0x40 + i);
            pq[1183] = (byte) (i + 1);
            result.add(new ObfuscationHybridRecipientKeys(x, pq));
            clear(x);
            clear(pq);
        }
        return result;
    }

    private static List<RecipientEntry> validEntries(int count) {
        List<RecipientEntry> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] rid = new byte[16];
            rid[0] = (byte) (i + 1);
            entries.add(new ObfuscationRecipient(rid, new byte[40], new byte[1088]));
            clear(rid);
        }
        return entries;
    }

    private static int firstIndexStartingWith(List<String> values, String prefix) {
        for (int i = 0; i < values.size(); i++) {
            if (values.get(i).startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static byte[] sequence(int length, int start) {
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

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static boolean allZero(byte[] value) {
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static final class Fixture {
        private final List<String> order;
        private final TrackingX25519Crypto x25519;
        private final TrackingMlKem768Crypto mlkem768;
        private final TrackingHkdfCrypto hkdf;
        private final TrackingKeyWrapCrypto keyWrap;
        private final TrackingSecureRandom random;

        private Fixture() {
            this(new ArrayList<>());
        }

        private Fixture(List<String> order) {
            this.order = order;
            this.x25519 = new TrackingX25519Crypto(order);
            this.mlkem768 = new TrackingMlKem768Crypto(order);
            this.hkdf = new TrackingHkdfCrypto(order);
            this.keyWrap = new TrackingKeyWrapCrypto(order);
            this.random = new TrackingSecureRandom(order);
        }

        private ObfuscationHybridRecipientBuilder builder() {
            return new ObfuscationHybridRecipientBuilder(
                    x25519,
                    mlkem768,
                    hkdf,
                    keyWrap,
                    random
            );
        }

        private void assertUnused() {
            assertEquals(0, x25519.generateCalls);
            assertEquals(0, x25519.deriveCalls);
            assertEquals(0, mlkem768.encapsulationCalls);
            assertEquals(0, hkdf.calls);
            assertEquals(0, keyWrap.calls);
            assertEquals(0, random.nextBytesCalls);
            assertEquals(0, random.nextIntCalls);
            assertTrue(order.isEmpty());
        }
    }

    private static final class TrackingHandle implements X25519PrivateKeyHandle {
        private final List<String> order;
        private int closeCalls;

        private TrackingHandle(List<String> order) {
            this.order = order;
        }

        @Override
        public byte[] publicKey() {
            order.add("publicKey");
            return filled(32, (byte) 0x7a);
        }

        @Override
        public void close() {
            closeCalls++;
            order.add("close");
        }
    }

    private static final class TrackingX25519Crypto implements X25519Crypto {
        private final List<String> order;
        private final List<TrackingHandle> handles = new ArrayList<>();
        private int generateCalls;
        private int deriveCalls;
        private Runnable onGenerate;

        private TrackingX25519Crypto(List<String> order) {
            this.order = order;
        }

        @Override
        public X25519PrivateKeyHandle generatePrivateKey() {
            generateCalls++;
            order.add("generate");
            if (onGenerate != null) {
                onGenerate.run();
            }
            TrackingHandle handle = new TrackingHandle(order);
            handles.add(handle);
            return handle;
        }

        @Override
        public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new AssertionError("importPrivateKey must not be called");
        }

        @Override
        public byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey) {
            deriveCalls++;
            order.add("derive");
            return filled(32, (byte) (0x10 + deriveCalls));
        }
    }

    private static final class TrackingMlKem768Crypto implements MLKem768Crypto {
        private final List<String> order;
        private final List<byte[]> publicKeySnapshots = new ArrayList<>();
        private final List<String> ekFingerprints = new ArrayList<>();
        private int encapsulationCalls;
        private RuntimeException failure;

        private TrackingMlKem768Crypto(List<String> order) {
            this.order = order;
        }

        @Override
        public MLKem768PrivateKeyHandle generatePrivateKey() {
            throw new AssertionError("generatePrivateKey must not be called");
        }

        @Override
        public MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new AssertionError("importPrivateKey must not be called");
        }

        @Override
        public MLKem768Encapsulation encapsulate(byte[] publicKey) {
            encapsulationCalls++;
            order.add("encap");
            publicKeySnapshots.add(publicKey.clone());
            if (failure != null) {
                throw failure;
            }
            byte[] ek = new byte[1088];
            ek[0] = (byte) encapsulationCalls;
            ek[1087] = (byte) (0x70 + encapsulationCalls);
            byte[] secret = filled(32, (byte) (0x20 + encapsulationCalls));
            ekFingerprints.add(Base64.getEncoder().encodeToString(ek));
            try {
                return new MLKem768Encapsulation(ek, secret);
            } finally {
                clear(ek);
                clear(secret);
            }
        }

        @Override
        public byte[] decapsulate(MLKem768PrivateKeyHandle privateKey, byte[] ciphertext) {
            throw new AssertionError("decapsulate must not be called by builder");
        }
    }

    private static final class TrackingHkdfCrypto implements HkdfCrypto {
        private final List<String> order;
        private final Deque<byte[]> scriptedRids = new ArrayDeque<>();
        private int calls;
        private int ridCalls;
        private int kekCalls;

        private TrackingHkdfCrypto(List<String> order) {
            this.order = order;
        }

        private void scriptRids(byte[]... rids) {
            for (byte[] rid : rids) {
                scriptedRids.addLast(rid.clone());
            }
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
            calls++;
            order.add("hkdf:" + length);
            if (length == 16) {
                ridCalls++;
                return scriptedRids.isEmpty()
                        ? filled(16, (byte) ridCalls)
                        : scriptedRids.removeFirst();
            }
            if (length == 32) {
                kekCalls++;
                return filled(32, (byte) (0x30 + kekCalls));
            }
            throw new AssertionError("unexpected HKDF output length");
        }
    }

    private static final class TrackingKeyWrapCrypto implements A256KeyWrapCrypto {
        private final List<String> order;
        private final List<byte[]> kekArguments = new ArrayList<>();
        private final List<byte[]> cekArguments = new ArrayList<>();
        private final List<byte[]> cekSnapshots = new ArrayList<>();
        private int calls;
        private RuntimeException failure;

        private TrackingKeyWrapCrypto(List<String> order) {
            this.order = order;
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            calls++;
            order.add("wrap");
            kekArguments.add(kek);
            cekArguments.add(keyToWrap);
            cekSnapshots.add(keyToWrap.clone());
            if (failure != null) {
                throw failure;
            }
            return filled(40, (byte) (0x50 + calls));
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new AssertionError("unwrap must not be called by builder");
        }

        private void assertSensitiveArgumentsCleared() {
            kekArguments.forEach(value -> assertTrue(allZero(value)));
            cekArguments.forEach(value -> assertTrue(allZero(value)));
        }
    }

    private static final class TrackingSecureRandom extends SecureRandom {
        private final List<String> order;
        private final Deque<byte[]> scriptedRids = new ArrayDeque<>();
        private final Deque<Integer> scriptedInts = new ArrayDeque<>();
        private final List<Integer> bounds = new ArrayList<>();
        private final List<String> generatedEkFingerprints = new ArrayList<>();
        private final List<String> generatedEncryptedKeyFingerprints = new ArrayList<>();
        private byte[] repeatedRid;
        private RuntimeException failure;
        private int nextBytesCalls;
        private int ridCalls;
        private int ekCalls;
        private int encryptedKeyCalls;
        private int nextIntCalls;

        private TrackingSecureRandom(List<String> order) {
            this.order = order;
        }

        private void scriptRids(byte[]... rids) {
            for (byte[] rid : rids) {
                scriptedRids.addLast(rid.clone());
            }
        }

        private void scriptNextInts(int... values) {
            for (int value : values) {
                scriptedInts.addLast(value);
            }
        }

        @Override
        public void nextBytes(byte[] bytes) {
            nextBytesCalls++;
            order.add("random:" + bytes.length);
            if (failure != null) {
                throw failure;
            }
            if (bytes.length == 16) {
                ridCalls++;
                byte[] source = !scriptedRids.isEmpty()
                        ? scriptedRids.removeFirst()
                        : repeatedRid != null
                        ? repeatedRid
                        : filled(16, (byte) (0x60 + ridCalls));
                System.arraycopy(source, 0, bytes, 0, bytes.length);
                return;
            }
            if (bytes.length == 1088) {
                ekCalls++;
                Arrays.fill(bytes, (byte) (0x20 + ekCalls));
                generatedEkFingerprints.add(Base64.getEncoder().encodeToString(bytes));
                return;
            }
            if (bytes.length == 40) {
                encryptedKeyCalls++;
                Arrays.fill(bytes, (byte) (0x40 + encryptedKeyCalls));
                generatedEncryptedKeyFingerprints.add(
                        Base64.getEncoder().encodeToString(bytes)
                );
                return;
            }
            throw new AssertionError("unexpected random byte length " + bytes.length);
        }

        @Override
        public int nextInt(int bound) {
            nextIntCalls++;
            bounds.add(bound);
            order.add("nextInt:" + bound);
            int value = scriptedInts.isEmpty() ? bound - 1 : scriptedInts.removeFirst();
            assertTrue(value >= 0 && value < bound);
            return value;
        }
    }
}
