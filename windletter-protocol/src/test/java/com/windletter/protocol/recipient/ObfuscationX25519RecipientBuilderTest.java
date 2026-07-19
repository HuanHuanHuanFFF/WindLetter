package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

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
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObfuscationX25519RecipientBuilderTest {

    private static final byte[] CEK = sequence(32, 0);

    @Test
    void buildsThreeRealRecipientsWithOneEpkAndEachReceiverUnwrapsTheSameCek() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        ObfuscationX25519RecipientBuilder builder =
                new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap);
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(x25519, hkdf);
        byte[] cek = CEK.clone();

        try (X25519PrivateKeyHandle first = x25519.generatePrivateKey();
             X25519PrivateKeyHandle second = x25519.generatePrivateKey();
             X25519PrivateKeyHandle third = x25519.generatePrivateKey()) {
            List<X25519PrivateKeyHandle> receivers = List.of(first, second, third);
            List<byte[]> publicKeys = List.of(first.publicKey(), second.publicKey(), third.publicKey());
            ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                    builder.build(publicKeys, cek);

            assertEquals("OKP", prepared.epk().kty());
            assertEquals("X25519", prepared.epk().crv());
            assertEquals(32, prepared.epk().x().length);
            assertEquals(8, prepared.recipients().size());
            assertRecipientShapeAndUniqueness(prepared.recipients());
            assertThrows(UnsupportedOperationException.class,
                    () -> prepared.recipients().add(prepared.recipients().get(0)));

            Set<Integer> matchedIndexes = new HashSet<>();
            for (X25519PrivateKeyHandle receiver : receivers) {
                byte[] epkX = prepared.epk().x();
                byte[] rid = null;
                byte[] kek = null;
                byte[] encryptedKey = null;
                byte[] unwrapped = null;
                try (ObfuscationX25519KeyDeriver.DerivedMaterial material =
                             deriver.derive(receiver, epkX)) {
                    rid = material.rid();
                    kek = material.kek();
                    int matchedIndex = findByRid(prepared.recipients(), rid);
                    assertTrue(matchedIndex >= 0, "real recipient rid must be present");
                    assertTrue(matchedIndexes.add(matchedIndex), "each receiver must match a distinct entry");
                    ObfuscationRecipient matched = assertInstanceOf(
                            ObfuscationRecipient.class,
                            prepared.recipients().get(matchedIndex)
                    );
                    encryptedKey = matched.encryptedKey();
                    unwrapped = keyWrap.unwrap(kek, encryptedKey);
                    assertArrayEquals(cek, unwrapped);
                } finally {
                    clear(epkX);
                    clear(rid);
                    clear(kek);
                    clear(encryptedKey);
                    clear(unwrapped);
                }
            }
            assertEquals(3, matchedIndexes.size());
            assertArrayEquals(CEK, cek);
            publicKeys.forEach(ObfuscationX25519RecipientBuilderTest::clear);
        } finally {
            clear(cek);
        }
    }

    @ParameterizedTest
    @CsvSource({"1,8", "8,8", "9,16", "16,16", "17,32", "32,32"})
    void padsToTheExactBucketWithUniformImmutableEntries(int realCount, int expectedCount) {
        Fixture fixture = new Fixture();

        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(trackingPeerKeys(realCount), CEK);

        assertEquals(expectedCount, prepared.recipients().size());
        assertRecipientShapeAndUniqueness(prepared.recipients());
        assertThrows(UnsupportedOperationException.class,
                () -> prepared.recipients().remove(0));
        assertEquals(1, fixture.x25519.generateCalls);
        assertEquals(realCount, fixture.x25519.deriveCalls);
        assertEquals(realCount, fixture.keyWrap.calls);
        assertEquals(1, fixture.x25519.handles.get(0).closeCalls);
        assertTrue(fixture.x25519.sharedSecrets.stream().allMatch(
                secret -> secret.length == 32 && !allZero(secret)
        ));
        fixture.keyWrap.assertSensitiveArgumentsCleared();
        fixture.hkdf.assertProviderOutputsCleared();
    }

    @Test
    void rejectsEveryInvalidDependencyAndBuildInputBeforeCryptoOrRandomness() {
        TrackingX25519Crypto x25519 = new TrackingX25519Crypto();
        TrackingHkdfCrypto hkdf = new TrackingHkdfCrypto();
        TrackingKeyWrapCrypto keyWrap = new TrackingKeyWrapCrypto();
        TrackingSecureRandom random = new TrackingSecureRandom();

        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder(null, hkdf, keyWrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder(x25519, null, keyWrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder(x25519, hkdf, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap, null));

        for (Arguments arguments : invalidBuildInputs().toList()) {
            Fixture fixture = new Fixture();
            Object[] values = arguments.get();
            @SuppressWarnings("unchecked")
            List<byte[]> keys = (List<byte[]>) values[1];
            byte[] cek = (byte[]) values[2];
            assertThrows(IllegalArgumentException.class,
                    () -> fixture.builder().build(keys, cek), (String) values[0]);
            fixture.assertUnused();
        }
        assertEquals(0, x25519.generateCalls);
        assertEquals(0, hkdf.calls);
        assertEquals(0, keyWrap.calls);
        assertEquals(0, random.totalCalls());
    }

    @Test
    void snapshotsAllInputsBeforeGenerationThenUsesOneHandleAndClosesItOnce() {
        byte[] first = filled(32, (byte) 0x21);
        byte[] second = filled(32, (byte) 0x22);
        byte[] expectedFirst = first.clone();
        byte[] expectedSecond = second.clone();
        byte[] cek = CEK.clone();
        byte[] expectedCek = cek.clone();
        List<byte[]> callerList = new ArrayList<>(List.of(first, second));
        List<String> order = new ArrayList<>();
        Fixture fixture = new Fixture(order);
        fixture.x25519.onGenerate = () -> {
            clear(first);
            clear(second);
            clear(cek);
            callerList.clear();
        };

        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(callerList, cek);

        assertEquals(1, fixture.x25519.generateCalls);
        assertEquals(2, fixture.x25519.deriveCalls);
        assertTrue(fixture.x25519.deriveHandles.stream().allMatch(
                handle -> handle == fixture.x25519.handles.get(0)
        ));
        assertArrayEquals(expectedFirst, fixture.x25519.peerSnapshots.get(0));
        assertArrayEquals(expectedSecond, fixture.x25519.peerSnapshots.get(1));
        fixture.keyWrap.cekSnapshots.forEach(snapshot -> assertArrayEquals(expectedCek, snapshot));
        assertEquals(1, fixture.x25519.handles.get(0).closeCalls);
        assertEquals("generate", order.get(0));
        assertEquals("publicKey", order.get(1));
        assertEquals("close", order.get(order.size() - 1));
        int firstRandomCall = order.indexOf("random:16");
        assertTrue(order.lastIndexOf("derive") < firstRandomCall);
        assertTrue(order.lastIndexOf("wrap") < firstRandomCall);
        assertTrue(order.indexOf("random:40") < order.indexOf("nextInt:8"));
        assertRecipientShapeAndUniqueness(prepared.recipients());
        fixture.keyWrap.assertSensitiveArgumentsCleared();
    }

    @Test
    void closesTheEphemeralExactlyOnceOnPublicKeyDeriveAndWrapFailures() {
        for (Object publicKeyOutcome : List.of(
                new IllegalStateException("public key failed"),
                new byte[31],
                new byte[33]
        )) {
            Fixture fixture = new Fixture();
            fixture.x25519.publicKeyOutcome = publicKeyOutcome;
            assertThrows(RuntimeException.class,
                    () -> fixture.builder().build(trackingPeerKeys(1), CEK));
            assertEquals(1, fixture.x25519.handles.get(0).closeCalls);
            assertEquals(0, fixture.x25519.deriveCalls);
            assertEquals(0, fixture.random.totalCalls());
        }
        Fixture nullPublicKey = new Fixture();
        nullPublicKey.x25519.publicKeyOutcome = NullOutcome.INSTANCE;
        assertThrows(IllegalStateException.class,
                () -> nullPublicKey.builder().build(trackingPeerKeys(1), CEK));
        assertEquals(1, nullPublicKey.x25519.handles.get(0).closeCalls);

        Fixture deriveFailure = new Fixture();
        CryptoOperationException deriveCause = new CryptoOperationException("derive failed");
        deriveFailure.x25519.deriveFailure = deriveCause;
        assertSame(deriveCause, assertThrows(CryptoOperationException.class,
                () -> deriveFailure.builder().build(trackingPeerKeys(1), CEK)));
        assertEquals(1, deriveFailure.x25519.handles.get(0).closeCalls);
        assertEquals(0, deriveFailure.keyWrap.calls);
        assertEquals(0, deriveFailure.random.totalCalls());

        Fixture success = new Fixture();
        success.builder().build(trackingPeerKeys(1), CEK);
        assertEquals(1, success.x25519.handles.get(0).closeCalls);
    }

    @Test
    void rejectsRealRidCollisionWithoutRegenerationOrPaddingAndResamplesDecoysGlobally() {
        byte[] collidingRid = filled(16, (byte) 0x31);
        Fixture realCollision = new Fixture();
        realCollision.hkdf.scriptRids(collidingRid, collidingRid);
        IllegalStateException collision = assertThrows(IllegalStateException.class,
                () -> realCollision.builder().build(trackingPeerKeys(2), CEK));
        assertTrue(collision.getMessage().toLowerCase().contains("real"));
        assertTrue(collision.getMessage().toLowerCase().contains("rid"));
        assertEquals(1, realCollision.x25519.generateCalls);
        assertEquals(2, realCollision.x25519.deriveCalls);
        assertEquals(2, realCollision.keyWrap.calls);
        assertEquals(0, realCollision.random.totalCalls());
        assertEquals(1, realCollision.x25519.handles.get(0).closeCalls);
        realCollision.keyWrap.assertSensitiveArgumentsCleared();

        Fixture resampling = new Fixture();
        byte[] realRid = filled(16, (byte) 0x41);
        byte[] firstDecoy = filled(16, (byte) 0x51);
        resampling.hkdf.scriptRids(realRid);
        resampling.random.scriptRids(realRid, firstDecoy, firstDecoy, filled(16, (byte) 0x52));
        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                resampling.builder().build(trackingPeerKeys(1), CEK);
        assertRecipientShapeAndUniqueness(prepared.recipients());
        assertEquals(9, resampling.random.ridCalls);
        assertEquals(1, resampling.x25519.handles.get(0).closeCalls);
    }

    @Test
    void limitsEachDecoyTo128RidAttemptsThenClosesAndClears() {
        byte[] realRid = filled(16, (byte) 0x61);
        Fixture fixture = new Fixture();
        fixture.hkdf.scriptRids(realRid);
        fixture.random.repeatedRid = realRid;

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> fixture.builder().build(trackingPeerKeys(1), CEK));

        assertTrue(failure.getMessage().toLowerCase().contains("decoy"));
        assertTrue(failure.getMessage().contains("128"));
        assertEquals(128, fixture.random.ridCalls);
        assertEquals(0, fixture.random.nextIntCalls);
        assertEquals(1, fixture.x25519.generateCalls);
        assertEquals(1, fixture.x25519.handles.get(0).closeCalls);
        fixture.keyWrap.assertSensitiveArgumentsCleared();
    }

    @ParameterizedTest
    @MethodSource("malformedWrappedOutputs")
    void rejectsMalformedWrappedOutputsAndMapsWrapFailuresWithClearing(
            String label,
            byte[] wrappedOutput
    ) {
        Fixture malformed = new Fixture();
        malformed.keyWrap.returnOutcome = wrappedOutput == null ? NullOutcome.INSTANCE : wrappedOutput;

        IllegalStateException malformedFailure = assertThrows(IllegalStateException.class,
                () -> malformed.builder().build(trackingPeerKeys(1), CEK), label);
        assertTrue(malformedFailure.getMessage().contains("A256KW"));
        if (wrappedOutput != null) {
            assertTrue(allZero(wrappedOutput));
        }
        assertEquals(1, malformed.x25519.handles.get(0).closeCalls);
        malformed.keyWrap.assertSensitiveArgumentsCleared();

        for (RuntimeException cause : List.of(
                new CryptoOperationException("provider crypto failure"),
                new UnsupportedOperationException("provider runtime failure")
        )) {
            Fixture failing = new Fixture();
            failing.keyWrap.returnOutcome = cause;
            IllegalStateException mapped = assertThrows(IllegalStateException.class,
                    () -> failing.builder().build(trackingPeerKeys(1), CEK));
            assertSame(cause, mapped.getCause());
            assertTrue(mapped.getMessage().contains("A256KW"));
            assertEquals(1, failing.x25519.handles.get(0).closeCalls);
            failing.keyWrap.assertSensitiveArgumentsCleared();
        }
    }

    @Test
    void usesExactFisherYatesBoundsAndMapsBothRandomFailureSites() {
        Fixture identity = new Fixture();
        byte[] realRid = filled(16, (byte) 0x25);
        identity.hkdf.scriptRids(realRid);
        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                identity.builder().build(trackingPeerKeys(1), CEK);
        assertEquals(List.of(8, 7, 6, 5, 4, 3, 2), identity.random.bounds);
        byte[] firstRid = assertInstanceOf(
                ObfuscationRecipient.class,
                prepared.recipients().get(0)
        ).rid();
        try {
            assertTrue(MessageDigest.isEqual(realRid, firstRid), "identity permutation is valid");
        } finally {
            clear(firstRid);
        }

        for (int failAt : List.of(1, 2)) {
            RuntimeException bytesCause =
                    new UnsupportedOperationException("nextBytes failed at " + failAt);
            Fixture bytesFailure = new Fixture();
            bytesFailure.random.nextBytesFailure = bytesCause;
            bytesFailure.random.failNextBytesAt = failAt;
            IllegalStateException bytesMapped = assertThrows(IllegalStateException.class,
                    () -> bytesFailure.builder().build(trackingPeerKeys(1), CEK));
            assertSame(bytesCause, bytesMapped.getCause());
            assertEquals(1, bytesFailure.x25519.handles.get(0).closeCalls);
            bytesFailure.keyWrap.assertSensitiveArgumentsCleared();
        }

        RuntimeException intCause = new UnsupportedOperationException("nextInt failed");
        Fixture intFailure = new Fixture();
        intFailure.random.nextIntFailure = intCause;
        intFailure.random.failNextIntAt = 1;
        IllegalStateException intMapped = assertThrows(IllegalStateException.class,
                () -> intFailure.builder().build(trackingPeerKeys(1), CEK));
        assertSame(intCause, intMapped.getCause());
        assertEquals(1, intFailure.x25519.handles.get(0).closeCalls);
        intFailure.keyWrap.assertSensitiveArgumentsCleared();
    }

    @Test
    void appliesACompleteScriptedNonIdentityFisherYatesPermutation() {
        Fixture fixture = new Fixture();
        byte[] realRid = filled(16, (byte) 0x26);
        fixture.hkdf.scriptRids(realRid);
        fixture.random.scriptNextInts(0, 0, 0, 0, 0, 0, 0);

        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(trackingPeerKeys(1), CEK);

        assertEquals(List.of(8, 7, 6, 5, 4, 3, 2), fixture.random.bounds);
        assertEquals(7, fixture.random.generatedRids.size());
        for (int i = 0; i < fixture.random.generatedRids.size(); i++) {
            byte[] actualRid = assertInstanceOf(
                    ObfuscationRecipient.class,
                    prepared.recipients().get(i)
            ).rid();
            try {
                assertArrayEquals(fixture.random.generatedRids.get(i), actualRid);
            } finally {
                clear(actualRid);
            }
        }
        byte[] finalRid = assertInstanceOf(
                ObfuscationRecipient.class,
                prepared.recipients().get(7)
        ).rid();
        try {
            assertArrayEquals(realRid, finalRid);
        } finally {
            clear(finalRid);
            fixture.random.clearGeneratedOutputs();
        }
    }

    @Test
    void copiesEveryInjectedRandomDecoyRidAndEncryptedKeyIntoTheWire() {
        Fixture fixture = new Fixture();
        byte[] realRid = filled(16, (byte) 0x27);
        fixture.hkdf.scriptRids(realRid);

        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                fixture.builder().build(trackingPeerKeys(1), CEK);

        assertEquals(7, fixture.random.generatedRids.size());
        assertEquals(7, fixture.random.generatedEncryptedKeys.size());
        try {
            for (int i = 0; i < fixture.random.generatedRids.size(); i++) {
                byte[] expectedRid = fixture.random.generatedRids.get(i);
                int wireIndex = findByRid(prepared.recipients(), expectedRid);
                assertTrue(wireIndex >= 0, "generated decoy rid must be present");
                byte[] actualEncryptedKey = assertInstanceOf(
                        ObfuscationRecipient.class,
                        prepared.recipients().get(wireIndex)
                ).encryptedKey();
                try {
                    assertArrayEquals(
                            fixture.random.generatedEncryptedKeys.get(i),
                            actualEncryptedKey
                    );
                } finally {
                    clear(actualEncryptedKey);
                }
            }
        } finally {
            fixture.random.clearGeneratedOutputs();
        }
    }

    @Test
    void consecutiveRealBuildsAreFreshAndAllCallerAndAccessorArraysAreDefensive() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        ObfuscationX25519RecipientBuilder builder =
                new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap);
        ObfuscationX25519KeyDeriver deriver = new ObfuscationX25519KeyDeriver(x25519, hkdf);
        byte[] cek = CEK.clone();

        try (X25519PrivateKeyHandle receiver = x25519.generatePrivateKey()) {
            byte[] publicKey = receiver.publicKey();
            ObfuscationX25519RecipientBuilder.PreparedRecipients first =
                    builder.build(List.of(publicKey), cek);
            ObfuscationX25519RecipientBuilder.PreparedRecipients second =
                    builder.build(List.of(publicKey), cek);
            byte[] firstEpk = first.epk().x();
            byte[] secondEpk = second.epk().x();
            byte[] firstRid = null;
            byte[] secondRid = null;
            try (ObfuscationX25519KeyDeriver.DerivedMaterial firstMaterial =
                         deriver.derive(receiver, firstEpk);
                 ObfuscationX25519KeyDeriver.DerivedMaterial secondMaterial =
                         deriver.derive(receiver, secondEpk)) {
                firstRid = firstMaterial.rid();
                secondRid = secondMaterial.rid();
                assertFalse(Arrays.equals(firstEpk, secondEpk));
                assertFalse(Arrays.equals(firstRid, secondRid));
                assertEquals(1, countRid(first.recipients(), firstRid));
                assertEquals(1, countRid(second.recipients(), secondRid));

                byte[] stableEpk = firstEpk.clone();
                ObfuscationRecipient firstEntry = assertInstanceOf(
                        ObfuscationRecipient.class,
                        first.recipients().get(0)
                );
                byte[] stableEntryRid = firstEntry.rid();
                byte[] stableEncryptedKey = firstEntry.encryptedKey();
                clear(publicKey);
                clear(cek);
                clear(firstEpk);
                clear(firstEntry.rid());
                clear(firstEntry.encryptedKey());
                assertArrayEquals(stableEpk, first.epk().x());
                assertArrayEquals(stableEntryRid, firstEntry.rid());
                assertArrayEquals(stableEncryptedKey, firstEntry.encryptedKey());
                clear(stableEpk);
                clear(stableEntryRid);
                clear(stableEncryptedKey);
            } finally {
                clear(publicKey);
                clear(firstEpk);
                clear(secondEpk);
                clear(firstRid);
                clear(secondRid);
            }
        } finally {
            clear(cek);
        }
    }

    @Test
    void preparedRecipientsConstructorEnforcesAndSnapshotsTheCompleteWireShape() {
        Epk validEpk = new Epk("OKP", "X25519", filled(32, (byte) 0x71));
        List<RecipientEntry> valid = validEntries(8);

        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(null, valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(
                        new Epk("EC", "X25519", new byte[32]), valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(
                        new Epk("OKP", "P-256", new byte[32]), valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(
                        new Epk("OKP", "X25519", new byte[31]), valid));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, validEntries(7)));

        List<RecipientEntry> nullEntry = new ArrayList<>(valid);
        nullEntry.set(0, null);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, nullEntry));
        List<RecipientEntry> publicEntry = new ArrayList<>(valid);
        publicEntry.set(0, new PublicRecipient(new RecipientKid("kid", null), new byte[40], null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, publicEntry));
        assertPreparedRejectsEntry(validEpk, valid,
                new ObfuscationRecipient(new byte[15], new byte[40], null));
        assertPreparedRejectsEntry(validEpk, valid,
                new ObfuscationRecipient(new byte[16], new byte[39], null));
        assertPreparedRejectsEntry(validEpk, valid,
                new ObfuscationRecipient(new byte[16], new byte[40], new byte[1]));
        List<RecipientEntry> duplicateRid = new ArrayList<>(valid);
        ObfuscationRecipient first = (ObfuscationRecipient) duplicateRid.get(0);
        duplicateRid.set(1, new ObfuscationRecipient(first.rid(), new byte[40], null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, duplicateRid));

        List<RecipientEntry> mutable = new ArrayList<>(valid);
        ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                new ObfuscationX25519RecipientBuilder.PreparedRecipients(validEpk, mutable);
        byte[] expectedEpk = validEpk.x();
        byte[] expectedRid = ((ObfuscationRecipient) mutable.get(0)).rid();
        mutable.clear();
        clear(validEpk.x());
        clear(((ObfuscationRecipient) valid.get(0)).rid());
        assertEquals(8, prepared.recipients().size());
        assertArrayEquals(expectedEpk, prepared.epk().x());
        assertArrayEquals(expectedRid,
                ((ObfuscationRecipient) prepared.recipients().get(0)).rid());
        assertThrows(UnsupportedOperationException.class,
                () -> prepared.recipients().clear());
        clear(expectedEpk);
        clear(expectedRid);
    }

    private static Stream<Arguments> invalidBuildInputs() {
        byte[] duplicate = filled(32, (byte) 0x11);
        return Stream.of(
                Arguments.of("null list", null, CEK.clone()),
                Arguments.of("empty list", List.of(), CEK.clone()),
                Arguments.of("33 recipients", trackingPeerKeys(33), CEK.clone()),
                Arguments.of("null item", Arrays.asList((byte[]) null), CEK.clone()),
                Arguments.of("31-byte key", List.of(new byte[31]), CEK.clone()),
                Arguments.of("33-byte key", List.of(new byte[33]), CEK.clone()),
                Arguments.of("duplicate key", List.of(duplicate, duplicate.clone()), CEK.clone()),
                Arguments.of("null CEK", trackingPeerKeys(1), null),
                Arguments.of("31-byte CEK", trackingPeerKeys(1), new byte[31]),
                Arguments.of("33-byte CEK", trackingPeerKeys(1), new byte[33])
        );
    }

    private static Stream<Arguments> malformedWrappedOutputs() {
        return Stream.of(
                Arguments.of("null", null),
                Arguments.of("39 bytes", new byte[39]),
                Arguments.of("41 bytes", new byte[41])
        );
    }

    private static void assertPreparedRejectsEntry(
            Epk epk,
            List<RecipientEntry> valid,
            RecipientEntry invalid
    ) {
        List<RecipientEntry> entries = new ArrayList<>(valid);
        entries.set(0, invalid);
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationX25519RecipientBuilder.PreparedRecipients(epk, entries));
    }

    private static void assertRecipientShapeAndUniqueness(List<RecipientEntry> entries) {
        Set<String> seen = new HashSet<>();
        for (RecipientEntry entry : entries) {
            ObfuscationRecipient recipient = assertInstanceOf(ObfuscationRecipient.class, entry);
            byte[] rid = recipient.rid();
            byte[] encryptedKey = recipient.encryptedKey();
            try {
                assertEquals(16, rid.length);
                assertEquals(40, encryptedKey.length);
                assertNull(recipient.ek());
                assertTrue(seen.add(Base64.getEncoder().encodeToString(rid)),
                        "all rids must be globally unique by content");
            } finally {
                clear(rid);
                clear(encryptedKey);
            }
        }
    }

    private static int findByRid(List<RecipientEntry> entries, byte[] expectedRid) {
        for (int i = 0; i < entries.size(); i++) {
            ObfuscationRecipient recipient = assertInstanceOf(ObfuscationRecipient.class, entries.get(i));
            byte[] candidate = recipient.rid();
            try {
                if (MessageDigest.isEqual(expectedRid, candidate)) {
                    return i;
                }
            } finally {
                clear(candidate);
            }
        }
        return -1;
    }

    private static int countRid(List<RecipientEntry> entries, byte[] expectedRid) {
        int matches = 0;
        for (RecipientEntry entry : entries) {
            ObfuscationRecipient recipient = assertInstanceOf(ObfuscationRecipient.class, entry);
            byte[] candidate = recipient.rid();
            try {
                if (MessageDigest.isEqual(expectedRid, candidate)) {
                    matches++;
                }
            } finally {
                clear(candidate);
            }
        }
        return matches;
    }

    private static List<byte[]> trackingPeerKeys(int count) {
        List<byte[]> keys = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] key = new byte[32];
            key[0] = (byte) (i + 1);
            key[31] = (byte) (0xa0 + i);
            keys.add(key);
        }
        return keys;
    }

    private static List<RecipientEntry> validEntries(int count) {
        List<RecipientEntry> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            entries.add(new ObfuscationRecipient(
                    filled(16, (byte) (i + 1)),
                    filled(40, (byte) (0x40 + i)),
                    null
            ));
        }
        return entries;
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

    private enum NullOutcome {
        INSTANCE
    }

    private static final class Fixture {
        private final List<String> order;
        private final TrackingX25519Crypto x25519;
        private final TrackingHkdfCrypto hkdf;
        private final TrackingKeyWrapCrypto keyWrap;
        private final TrackingSecureRandom random;

        private Fixture() {
            this(new ArrayList<>());
        }

        private Fixture(List<String> order) {
            this.order = order;
            this.x25519 = new TrackingX25519Crypto(order);
            this.hkdf = new TrackingHkdfCrypto(order);
            this.keyWrap = new TrackingKeyWrapCrypto(order);
            this.random = new TrackingSecureRandom(order);
        }

        private ObfuscationX25519RecipientBuilder builder() {
            return new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap, random);
        }

        private void assertUnused() {
            assertEquals(0, x25519.generateCalls);
            assertEquals(0, x25519.deriveCalls);
            assertEquals(0, hkdf.calls);
            assertEquals(0, keyWrap.calls);
            assertEquals(0, random.totalCalls());
            assertTrue(order.isEmpty());
        }
    }

    private static final class TrackingHandle implements X25519PrivateKeyHandle {
        private final Object publicKeyOutcome;
        private final List<String> order;
        private int closeCalls;

        private TrackingHandle(Object publicKeyOutcome, List<String> order) {
            this.publicKeyOutcome = publicKeyOutcome;
            this.order = order;
        }

        @Override
        public byte[] publicKey() {
            order.add("publicKey");
            if (publicKeyOutcome instanceof RuntimeException failure) {
                throw failure;
            }
            if (publicKeyOutcome == NullOutcome.INSTANCE) {
                return null;
            }
            return ((byte[]) publicKeyOutcome).clone();
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
        private final List<X25519PrivateKeyHandle> deriveHandles = new ArrayList<>();
        private final List<byte[]> peerSnapshots = new ArrayList<>();
        private final List<byte[]> sharedSecrets = new ArrayList<>();
        private Object publicKeyOutcome = filled(32, (byte) 0x7a);
        private RuntimeException deriveFailure;
        private Runnable onGenerate;
        private int generateCalls;
        private int deriveCalls;

        private TrackingX25519Crypto() {
            this(new ArrayList<>());
        }

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
            TrackingHandle handle = new TrackingHandle(publicKeyOutcome, order);
            handles.add(handle);
            return handle;
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
            deriveCalls++;
            order.add("derive");
            deriveHandles.add(privateKey);
            peerSnapshots.add(peerPublicKey.clone());
            if (deriveFailure != null) {
                throw deriveFailure;
            }
            byte[] shared = filled(32, (byte) (0x10 + deriveCalls));
            sharedSecrets.add(shared.clone());
            return shared;
        }
    }

    private static final class TrackingHkdfCrypto implements HkdfCrypto {
        private final List<String> order;
        private final Deque<byte[]> scriptedRids = new ArrayDeque<>();
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private int calls;
        private int ridCalls;
        private int kekCalls;

        private TrackingHkdfCrypto() {
            this(new ArrayList<>());
        }

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
            byte[] output;
            if (length == 16) {
                ridCalls++;
                output = scriptedRids.isEmpty()
                        ? filled(16, (byte) ridCalls)
                        : scriptedRids.removeFirst();
            } else if (length == 32) {
                kekCalls++;
                output = filled(32, (byte) (0x30 + kekCalls));
            } else {
                throw new AssertionError("unexpected HKDF length " + length);
            }
            providerOutputs.add(output);
            return output;
        }

        private void assertProviderOutputsCleared() {
            providerOutputs.forEach(output -> assertTrue(allZero(output)));
        }
    }

    private static final class TrackingKeyWrapCrypto implements A256KeyWrapCrypto {
        private final List<String> order;
        private final List<byte[]> kekArguments = new ArrayList<>();
        private final List<byte[]> cekArguments = new ArrayList<>();
        private final List<byte[]> cekSnapshots = new ArrayList<>();
        private Object returnOutcome;
        private int calls;

        private TrackingKeyWrapCrypto() {
            this(new ArrayList<>());
        }

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
            if (returnOutcome instanceof RuntimeException failure) {
                throw failure;
            }
            if (returnOutcome == NullOutcome.INSTANCE) {
                return null;
            }
            if (returnOutcome instanceof byte[] scripted) {
                return scripted;
            }
            return filled(40, (byte) (0x50 + calls));
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new AssertionError("unwrap must not be called by builder");
        }

        private void assertSensitiveArgumentsCleared() {
            kekArguments.forEach(argument -> assertTrue(allZero(argument), "temporary KEK must clear"));
            cekArguments.forEach(argument -> assertTrue(allZero(argument), "CEK snapshot must clear"));
        }
    }

    private static final class TrackingSecureRandom extends SecureRandom {
        private final List<String> order;
        private final Deque<byte[]> scriptedRids = new ArrayDeque<>();
        private final Deque<Integer> scriptedInts = new ArrayDeque<>();
        private final List<Integer> bounds = new ArrayList<>();
        private final List<byte[]> generatedRids = new ArrayList<>();
        private final List<byte[]> generatedEncryptedKeys = new ArrayList<>();
        private byte[] repeatedRid;
        private RuntimeException nextBytesFailure;
        private RuntimeException nextIntFailure;
        private int failNextBytesAt = -1;
        private int failNextIntAt = -1;
        private int nextBytesCalls;
        private int ridCalls;
        private int encryptedKeyCalls;
        private int nextIntCalls;

        private TrackingSecureRandom() {
            this(new ArrayList<>());
        }

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
            if (nextBytesCalls == failNextBytesAt) {
                throw nextBytesFailure;
            }
            if (bytes.length == 16) {
                ridCalls++;
                byte[] source;
                if (!scriptedRids.isEmpty()) {
                    source = scriptedRids.removeFirst();
                } else if (repeatedRid != null) {
                    source = repeatedRid;
                } else {
                    source = filled(16, (byte) (0x70 + ridCalls));
                }
                System.arraycopy(source, 0, bytes, 0, bytes.length);
                generatedRids.add(bytes.clone());
                return;
            }
            if (bytes.length == 40) {
                encryptedKeyCalls++;
                Arrays.fill(bytes, (byte) (0x20 + encryptedKeyCalls));
                generatedEncryptedKeys.add(bytes.clone());
                return;
            }
            throw new AssertionError("unexpected random byte length " + bytes.length);
        }

        @Override
        public int nextInt(int bound) {
            nextIntCalls++;
            bounds.add(bound);
            order.add("nextInt:" + bound);
            if (nextIntCalls == failNextIntAt) {
                throw nextIntFailure;
            }
            int result = scriptedInts.isEmpty() ? bound - 1 : scriptedInts.removeFirst();
            if (result < 0 || result >= bound) {
                throw new AssertionError("scripted nextInt result outside bound");
            }
            return result;
        }

        private int totalCalls() {
            return nextBytesCalls + nextIntCalls;
        }

        private void clearGeneratedOutputs() {
            generatedRids.forEach(ObfuscationX25519RecipientBuilderTest::clear);
            generatedEncryptedKeys.forEach(ObfuscationX25519RecipientBuilderTest::clear);
            generatedRids.clear();
            generatedEncryptedKeys.clear();
        }
    }
}
