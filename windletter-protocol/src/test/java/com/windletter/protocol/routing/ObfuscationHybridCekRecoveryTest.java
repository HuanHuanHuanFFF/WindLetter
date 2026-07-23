package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
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
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientBuilder;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientKeys;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiPredicate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObfuscationHybridCekRecoveryTest {

    private static final Epk VALID_EPK = new Epk("OKP", "X25519", filled(32, 0x55));

    @Test
    void privateKeyPairAndRecoveryDependenciesRejectNull() {
        XHandle x = XHandle.returning(filled(32, 1));
        PqHandle pq = PqHandle.returning(filled(1184, 2));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientPrivateKeys(null, pq));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridRecipientPrivateKeys(x, null));

        Fixture fixture = new Fixture();
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridCekRecovery(null, fixture.keyWrap));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridCekRecovery(fixture.deriver(), null));
        assertThrows(IllegalArgumentException.class,
                () -> new ObfuscationHybridCekRecovery(
                        fixture.deriver(), fixture.keyWrap, null));
    }

    @Test
    void realBuilderWireRecoversAndWrongKemEntriesBecomeNotForMeAfterFullScan() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        byte[] cek = sequence(32, 0x20);

        try (X25519PrivateKeyHandle x = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle pq = mlkem768.generatePrivateKey();
             X25519PrivateKeyHandle unrelatedX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle unrelatedPq = mlkem768.generatePrivateKey()) {
            ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                    new ObfuscationHybridRecipientBuilder(x25519, mlkem768, hkdf, keyWrap)
                            .build(List.of(new ObfuscationHybridRecipientKeys(
                                    x.publicKey(), pq.publicKey())), cek);
            TrackingComparator comparator = new TrackingComparator();
            ObfuscationHybridCekRecovery recovery = new ObfuscationHybridCekRecovery(
                    new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf),
                    keyWrap,
                    comparator
            );
            ObfuscationHybridRecipientPrivateKeys target =
                    new ObfuscationHybridRecipientPrivateKeys(x, pq);
            ObfuscationHybridRecipientPrivateKeys unrelated =
                    new ObfuscationHybridRecipientPrivateKeys(unrelatedX, unrelatedPq);

            byte[] recovered = recovery.recover(
                    prepared.epk(), prepared.recipients(), List.of(target));
            try {
                assertArrayEquals(cek, recovered);
            } finally {
                clear(recovered);
            }
            assertEquals(8, comparator.comparisons);
            assertCode(ErrorCode.NOT_FOR_ME,
                    () -> recovery.recover(
                            prepared.epk(), prepared.recipients(), List.of(unrelated)));
            assertEquals(16, comparator.comparisons);
            assertCode(ErrorCode.NOT_FOR_ME,
                    () -> recovery.recover(prepared.epk(), rotateEks(prepared.recipients()),
                            List.of(target)));
            assertEquals(24, comparator.comparisons);
            comparator.candidateReferences.forEach(value -> assertTrue(allZero(value)));
            comparator.wireReferences.forEach(value -> assertTrue(allZero(value)));
            assertEquals(32, x.publicKey().length);
            assertEquals(1184, pq.publicKey().length);
        } finally {
            clear(cek);
        }
    }

    @Test
    void validatesWholeWireAndDuplicateRidsBeforeReadingAnyLocalHandle() {
        Fixture fixture = new Fixture();
        ObfuscationHybridRecipientPrivateKeys local = fixture.pair(1, 0x10);
        List<RecipientEntry> duplicate = uniqueWire();
        duplicate.set(7, wire(0x66, 8, 0x57));
        duplicate.set(2, wire(0x66, 3, 0x52));

        ProtocolException duplicateFailure = assertCode(
                ErrorCode.INVALID_FIELD,
                () -> fixture.recovery().recover(VALID_EPK, duplicate, null));
        assertTrue(duplicateFailure.getMessage().contains("duplicate"));
        assertEquals(0, fixture.xHandles.get(0).publicKeyCalls);
        assertEquals(0, fixture.pqHandles.get(0).publicKeyCalls);
        assertEquals(0, fixture.x25519.deriveCalls);

        List<Runnable> malformed = new ArrayList<>();
        malformed.add(() -> fixture.recovery().recover(null, uniqueWire(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                new Epk("EC", "X25519", new byte[32]), uniqueWire(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                new Epk("OKP", "X25519", new byte[31]), uniqueWire(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(VALID_EPK, null, List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, uniqueWire().subList(0, 7), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK,
                replacing(0, new PublicRecipient(
                        new RecipientKid("kid", null), new byte[40], null)),
                List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK,
                replacing(0, new ObfuscationRecipient(
                        new byte[15], new byte[40], new byte[1088])),
                List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK,
                replacing(0, new ObfuscationRecipient(
                        new byte[16], new byte[39], new byte[1088])),
                List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK,
                replacing(0, new ObfuscationRecipient(
                        new byte[16], new byte[40], null)),
                List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK,
                replacing(7, new ObfuscationRecipient(
                        new byte[16], new byte[40], new byte[1087])),
                List.of(local)));
        for (Runnable operation : malformed) {
            assertCode(ErrorCode.INVALID_FIELD, operation);
            assertEquals(0, fixture.xHandles.get(0).publicKeyCalls);
            assertEquals(0, fixture.pqHandles.get(0).publicKeyCalls);
            assertEquals(0, fixture.x25519.deriveCalls);
            assertEquals(0, fixture.mlkem768.decapsulationCalls);
        }
    }

    @Test
    void localPairsAreAtomicRejectOnlyExactDuplicatesAndRemainBorrowed() {
        Fixture nullList = new Fixture();
        assertCode(ErrorCode.INTERNAL_ERROR,
                () -> nullList.recovery().recover(VALID_EPK, uniqueWire(), null));
        List<ObfuscationHybridRecipientPrivateKeys> containingNull = new ArrayList<>();
        containingNull.add(null);
        assertCode(ErrorCode.INTERNAL_ERROR,
                () -> nullList.recovery().recover(
                        VALID_EPK, uniqueWire(), containingNull));
        List<ObfuscationHybridRecipientPrivateKeys> unsnapshotable = new AbstractList<>() {
            @Override
            public ObfuscationHybridRecipientPrivateKeys get(int index) {
                throw new IllegalStateException("snapshot failed");
            }

            @Override
            public int size() {
                return 1;
            }
        };
        ProtocolException snapshotFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> nullList.recovery().recover(
                        VALID_EPK, uniqueWire(), unsnapshotable)
        );
        assertTrue(snapshotFailure.getCause() instanceof IllegalStateException);

        Fixture duplicate = new Fixture();
        ObfuscationHybridRecipientPrivateKeys first = duplicate.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys samePublicPair = duplicate.pair(1, 0x10);
        assertCode(ErrorCode.INTERNAL_ERROR,
                () -> duplicate.recovery().recover(
                        VALID_EPK, uniqueWire(), List.of(first, samePublicPair)));
        assertEquals(0, duplicate.x25519.deriveCalls);
        assertEquals(0, duplicate.mlkem768.decapsulationCalls);

        Fixture shared = new Fixture();
        ObfuscationHybridRecipientPrivateKeys a = shared.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys sameX = shared.pair(1, 0x20);
        ObfuscationHybridRecipientPrivateKeys samePq = shared.pair(2, 0x10);
        assertCode(ErrorCode.NOT_FOR_ME,
                () -> shared.recovery().recover(
                        VALID_EPK, uniqueWire(), List.of(a, sameX, samePq)));
        assertEquals(3, shared.x25519.deriveCalls);
        assertEquals(24, shared.mlkem768.decapsulationCalls);
        assertEquals(48, shared.hkdf.calls);
        assertEquals(24, shared.comparator.comparisons);
        shared.assertBorrowedHandlesOpen();
        shared.assertSensitiveReferencesCleared();
    }

    @Test
    void scansWireOuterLocalInnerForFirstMiddleAndLastMatchesWithoutEarlyExit() {
        for (int wireIndex : List.of(0, 3, 7)) {
            Fixture fixture = new Fixture();
            ObfuscationHybridRecipientPrivateKeys first = fixture.pair(1, 0x10);
            ObfuscationHybridRecipientPrivateKeys matching = fixture.pair(2, 0x20);
            List<RecipientEntry> wire = uniqueWire();
            wire.set(wireIndex, wire(
                    derivedRidMarker(2, 0x20, wireIndex + 1),
                    wireIndex + 1,
                    0x50 + wireIndex
            ));

            byte[] recovered = fixture.recovery().recover(
                    VALID_EPK, wire, List.of(first, matching));

            assertEquals(16, fixture.mlkem768.decapsulationCalls);
            assertEquals(32, fixture.hkdf.calls);
            assertEquals(16, fixture.comparator.comparisons);
            assertEquals(1, fixture.keyWrap.unwrapCalls);
            assertEquals(0x50 + wireIndex, Byte.toUnsignedInt(recovered[0]));
            assertEquals(expectedScanOrder(), fixture.mlkem768.order);
            fixture.assertBorrowedHandlesOpen();
            fixture.assertSensitiveReferencesCleared();
            clear(recovered);
        }
    }

    @Test
    void tieBreakIsSmallestWireThenLocalAndSelectedUnwrapNeverFallsBack() {
        Fixture wireTie = new Fixture();
        ObfuscationHybridRecipientPrivateKeys localForLater = wireTie.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys localForFirst = wireTie.pair(2, 0x20);
        List<RecipientEntry> wire = uniqueWire();
        wire.set(0, wire(derivedRidMarker(2, 0x20, 1), 1, 0x61));
        wire.set(5, wire(derivedRidMarker(1, 0x10, 6), 6, 0x66));
        byte[] recovered = wireTie.recovery().recover(
                VALID_EPK, wire, List.of(localForLater, localForFirst));
        assertEquals(0x61, Byte.toUnsignedInt(recovered[0]));
        assertEquals(1, wireTie.keyWrap.unwrapCalls);
        clear(recovered);

        Fixture localTie = new Fixture();
        localTie.hkdf.constantRid = filled(16, 0x44);
        ObfuscationHybridRecipientPrivateKeys local0 = localTie.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys local1 = localTie.pair(2, 0x20);
        List<RecipientEntry> sameWireMatch = uniqueWire();
        sameWireMatch.set(2, wire(0x44, 3, 0x63));
        byte[] localTieRecovered = localTie.recovery().recover(
                VALID_EPK, sameWireMatch, List.of(local0, local1));
        assertEquals(
                derivedRidMarker(1, 0x10, 3) + 0x40,
                Byte.toUnsignedInt(localTie.keyWrap.kekSnapshot[0])
        );
        assertEquals(16, localTie.comparator.comparisons);
        clear(localTieRecovered);
        clear(localTie.hkdf.constantRid);

        Fixture noFallback = new Fixture();
        ObfuscationHybridRecipientPrivateKeys nf0 = noFallback.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys nf1 = noFallback.pair(2, 0x20);
        List<RecipientEntry> twoMatches = uniqueWire();
        twoMatches.set(0, wire(derivedRidMarker(2, 0x20, 1), 1, 0x71));
        twoMatches.set(1, wire(derivedRidMarker(1, 0x10, 2), 2, 0x72));
        noFallback.keyWrap.failure = new CryptoOperationException("integrity");
        assertAttackerFailure(() -> noFallback.recovery().recover(
                VALID_EPK, twoMatches, List.of(nf0, nf1)));
        assertEquals(16, noFallback.comparator.comparisons);
        assertEquals(1, noFallback.keyWrap.unwrapCalls);
        assertEquals(0x71, Byte.toUnsignedInt(noFallback.keyWrap.wrappedSnapshot[0]));
        noFallback.assertSensitiveReferencesCleared();
        noFallback.assertBorrowedHandlesOpen();
    }

    @Test
    void candidateFailuresLatchGloballyStillCompareEveryCombinationAndNeverUnwrap() {
        for (int failAt : List.of(1, 8, 16)) {
            Fixture mlFailure = new Fixture();
            ObfuscationHybridRecipientPrivateKeys ml0 = mlFailure.pair(1, 0x10);
            ObfuscationHybridRecipientPrivateKeys ml1 = mlFailure.pair(2, 0x20);
            mlFailure.mlkem768.failure = new CryptoOperationException("bad ek");
            mlFailure.mlkem768.failAtCall = failAt;
            List<RecipientEntry> mlWire = uniqueWire();
            mlWire.set(0, wire(
                    failAt == 1 ? 1 : derivedRidMarker(1, 0x10, 1),
                    1,
                    0x51
            ));
            mlWire.set(7, wire(derivedRidMarker(2, 0x20, 8), 8, 0x58));
            assertAttackerFailure(() -> mlFailure.recovery().recover(
                    VALID_EPK, mlWire, List.of(ml0, ml1)));
            assertEquals(16, mlFailure.mlkem768.decapsulationCalls);
            assertEquals(32, mlFailure.hkdf.calls);
            assertEquals(16, mlFailure.comparator.comparisons);
            assertEquals(0, mlFailure.keyWrap.unwrapCalls);
            mlFailure.assertSensitiveReferencesCleared();
            mlFailure.assertBorrowedHandlesOpen();
        }

        Fixture xFailure = new Fixture();
        ObfuscationHybridRecipientPrivateKeys x0 = xFailure.pair(1, 0x10);
        ObfuscationHybridRecipientPrivateKeys x1 = xFailure.pair(2, 0x20);
        xFailure.x25519.failure = new CryptoOperationException("low order");
        xFailure.x25519.failAtCall = 0;
        List<RecipientEntry> xWire = uniqueWire();
        xWire.set(0, wire(0x11, 1, 0x51));
        xWire.set(7, wire(derivedRidMarker(2, 0x20, 8), 8, 0x58));
        assertAttackerFailure(() -> xFailure.recovery().recover(
                VALID_EPK, xWire, List.of(x0, x1)));
        assertEquals(2, xFailure.x25519.deriveCalls);
        assertEquals(16, xFailure.mlkem768.decapsulationCalls);
        assertEquals(32, xFailure.hkdf.calls);
        assertEquals(16, xFailure.comparator.comparisons);
        assertEquals(0, xFailure.keyWrap.unwrapCalls);
        xFailure.assertSensitiveReferencesCleared();
        xFailure.assertBorrowedHandlesOpen();
    }

    @Test
    void realLowOrderEpkFailureLatchesEveryLocalPairAndStillRunsFullDummyScan() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        TrackingMlKem768 mlkem768 = new TrackingMlKem768();
        TrackingHkdf hkdf = new TrackingHkdf();
        TrackingKeyWrap keyWrap = new TrackingKeyWrap();
        TrackingComparator comparator = new TrackingComparator();
        PqHandle pq0 = PqHandle.returning(filled(1184, 0x10));
        PqHandle pq1 = PqHandle.returning(filled(1184, 0x20));
        try (X25519PrivateKeyHandle x0 = x25519.generatePrivateKey();
             X25519PrivateKeyHandle x1 = x25519.generatePrivateKey()) {
            ObfuscationHybridCekRecovery recovery = new ObfuscationHybridCekRecovery(
                    new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf),
                    keyWrap,
                    comparator
            );
            List<ObfuscationHybridRecipientPrivateKeys> pairs = List.of(
                    new ObfuscationHybridRecipientPrivateKeys(x0, pq0),
                    new ObfuscationHybridRecipientPrivateKeys(x1, pq1)
            );

            assertAttackerFailure(() -> recovery.recover(
                    new Epk("OKP", "X25519", new byte[32]),
                    uniqueWire(),
                    pairs
            ));
            assertEquals(16, mlkem768.decapsulationCalls);
            assertEquals(32, hkdf.calls);
            assertEquals(16, comparator.comparisons);
            assertEquals(0, keyWrap.unwrapCalls);
            assertEquals(32, x0.publicKey().length);
            assertEquals(32, x1.publicKey().length);
            assertEquals(0, pq0.closeCalls);
            assertEquals(0, pq1.closeCalls);
            mlkem768.providerOutputs.forEach(value -> assertTrue(allZero(value)));
            hkdf.providerOutputs.forEach(value -> assertTrue(allZero(value)));
            comparator.candidateReferences.forEach(value -> assertTrue(allZero(value)));
            comparator.wireReferences.forEach(value -> assertTrue(allZero(value)));
        }
    }

    @Test
    void emptyAndUnrelatedPairsAreNotForMeWhileContractsRemainInternal() {
        Fixture empty = new Fixture();
        assertCode(ErrorCode.NOT_FOR_ME,
                () -> empty.recovery().recover(VALID_EPK, uniqueWire(), List.of()));
        assertEquals(0, empty.x25519.deriveCalls);
        assertEquals(0, empty.mlkem768.decapsulationCalls);

        Fixture malformedX = new Fixture();
        malformedX.xHandles.add(XHandle.returning(new byte[31]));
        malformedX.pqHandles.add(PqHandle.returning(new byte[1184]));
        ObfuscationHybridRecipientPrivateKeys badX =
                new ObfuscationHybridRecipientPrivateKeys(
                        malformedX.xHandles.get(0), malformedX.pqHandles.get(0));
        assertCode(ErrorCode.INTERNAL_ERROR,
                () -> malformedX.recovery().recover(
                        VALID_EPK, uniqueWire(), List.of(badX)));

        Fixture malformedPq = new Fixture();
        RuntimeException closed = new IllegalStateException("closed");
        malformedPq.xHandles.add(XHandle.returning(new byte[32]));
        malformedPq.pqHandles.add(PqHandle.throwing(closed));
        ObfuscationHybridRecipientPrivateKeys badPq =
                new ObfuscationHybridRecipientPrivateKeys(
                        malformedPq.xHandles.get(0), malformedPq.pqHandles.get(0));
        ProtocolException localFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> malformedPq.recovery().recover(
                        VALID_EPK, uniqueWire(), List.of(badPq)));
        assertSame(closed, localFailure.getCause());

        Fixture hkdfFailure = new Fixture();
        ObfuscationHybridRecipientPrivateKeys pair = hkdfFailure.pair(1, 0x10);
        RuntimeException hkdfCause = new CryptoOperationException("hkdf down");
        hkdfFailure.hkdf.failure = hkdfCause;
        ProtocolException derivedFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> hkdfFailure.recovery().recover(
                        VALID_EPK, uniqueWire(), List.of(pair)));
        assertTrue(derivedFailure.getCause() instanceof IllegalStateException);
        assertSame(hkdfCause, derivedFailure.getCause().getCause());

        for (Object outcome : List.of(NullOutcome.INSTANCE, new byte[31], new byte[33])) {
            Fixture malformedUnwrap = matchingFixture();
            malformedUnwrap.keyWrap.outcome = outcome;
            assertCode(ErrorCode.INTERNAL_ERROR,
                    () -> malformedUnwrap.recovery().recover(
                            VALID_EPK, matchingWire(1, 0x10, 3),
                            malformedUnwrap.pairs()));
            assertEquals(1, malformedUnwrap.keyWrap.unwrapCalls);
            malformedUnwrap.assertSensitiveReferencesCleared();
            malformedUnwrap.assertBorrowedHandlesOpen();
        }
        Fixture nonCryptoUnwrap = matchingFixture();
        RuntimeException providerBug = new IllegalStateException("provider bug");
        nonCryptoUnwrap.keyWrap.failure = providerBug;
        ProtocolException unwrapFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> nonCryptoUnwrap.recovery().recover(
                        VALID_EPK, matchingWire(1, 0x10, 3),
                        nonCryptoUnwrap.pairs()));
        assertSame(providerBug, unwrapFailure.getCause());
        nonCryptoUnwrap.assertSensitiveReferencesCleared();
        nonCryptoUnwrap.assertBorrowedHandlesOpen();

        Fixture comparatorFailure = matchingFixture();
        ProtocolException injected = new ProtocolException(
                ErrorCode.NOT_FOR_ME,
                "test comparator failure"
        );
        ObfuscationHybridCekRecovery comparatorFailingRecovery =
                new ObfuscationHybridCekRecovery(
                        comparatorFailure.deriver(),
                        comparatorFailure.keyWrap,
                        (candidate, wireRid) -> {
                            throw injected;
                        }
                );
        ProtocolException mappedComparatorFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> comparatorFailingRecovery.recover(
                        VALID_EPK,
                        matchingWire(1, 0x10, 3),
                        comparatorFailure.pairs()
                )
        );
        assertSame(injected, mappedComparatorFailure.getCause());
        comparatorFailure.assertSensitiveReferencesCleared();
        comparatorFailure.assertBorrowedHandlesOpen();
    }

    @Test
    void successReturnsCallerOwnedCopyAndClearsEveryOwnedSnapshot() {
        Fixture fixture = matchingFixture();
        byte[] recovered = fixture.recovery().recover(
                VALID_EPK, matchingWire(1, 0x10, 3), fixture.pairs());
        byte[] providerResult = fixture.keyWrap.providerResult;

        assertNotSame(providerResult, recovered);
        assertTrue(allZero(providerResult));
        assertFalse(allZero(recovered));
        fixture.assertSensitiveReferencesCleared();
        fixture.assertBorrowedHandlesOpen();
        byte original = recovered[1];
        providerResult[1] = 0x7f;
        assertEquals(original, recovered[1]);
        clear(providerResult);
        clear(recovered);
    }

    private static Fixture matchingFixture() {
        Fixture fixture = new Fixture();
        fixture.pair(1, 0x10);
        return fixture;
    }

    private static List<RecipientEntry> matchingWire(int xMarker, int pqMarker, int index) {
        List<RecipientEntry> wire = uniqueWire();
        int ekMarker = index + 1;
        wire.set(index, wire(
                derivedRidMarker(xMarker, pqMarker, ekMarker),
                ekMarker,
                0x50 + index
        ));
        return wire;
    }

    private static int derivedRidMarker(int xMarker, int pqMarker, int ekMarker) {
        return (xMarker + pqMarker + ekMarker) & 0xff;
    }

    private static List<String> expectedScanOrder() {
        List<String> order = new ArrayList<>();
        for (int wire = 1; wire <= 8; wire++) {
            order.add(wire + ":16");
            order.add(wire + ":32");
        }
        return order;
    }

    private static List<RecipientEntry> uniqueWire() {
        List<RecipientEntry> result = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            result.add(wire(0x70 + i, i + 1, 0x50 + i));
        }
        return result;
    }

    private static List<RecipientEntry> replacing(int index, RecipientEntry replacement) {
        List<RecipientEntry> result = uniqueWire();
        result.set(index, replacement);
        return result;
    }

    private static ObfuscationRecipient wire(int ridMarker, int ekMarker, int encryptedMarker) {
        byte[] ek = new byte[1088];
        ek[0] = (byte) ekMarker;
        ek[1087] = (byte) (0x40 + ekMarker);
        return new ObfuscationRecipient(
                filled(16, ridMarker), filled(40, encryptedMarker), ek);
    }

    private static List<RecipientEntry> rotateEks(List<RecipientEntry> source) {
        List<byte[]> eks = new ArrayList<>();
        for (RecipientEntry entry : source) {
            eks.add(((ObfuscationRecipient) entry).ek());
        }
        List<RecipientEntry> rotated = new ArrayList<>();
        try {
            for (int i = 0; i < source.size(); i++) {
                ObfuscationRecipient recipient = (ObfuscationRecipient) source.get(i);
                byte[] rid = recipient.rid();
                byte[] encrypted = recipient.encryptedKey();
                try {
                    rotated.add(new ObfuscationRecipient(
                            rid,
                            encrypted,
                            eks.get((i + 1) % eks.size())
                    ));
                } finally {
                    clear(rid);
                    clear(encrypted);
                }
            }
            return rotated;
        } finally {
            eks.forEach(ObfuscationHybridCekRecoveryTest::clear);
        }
    }

    private static ProtocolException assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        return failure;
    }

    private static void assertAttackerFailure(Runnable operation) {
        ProtocolException failure = assertCode(ErrorCode.KEY_UNWRAP_FAILED, operation);
        assertEquals("obfuscation hybrid recipient key recovery failed", failure.getMessage());
        assertNull(failure.getCause());
    }

    private static byte[] sequence(int length, int start) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }

    private static byte[] filled(int length, int marker) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) marker);
        return result;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static boolean allZero(byte[] value) {
        if (value == null) {
            return true;
        }
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private enum NullOutcome { INSTANCE }

    private static final class Fixture {
        private final TrackingX25519 x25519 = new TrackingX25519();
        private final TrackingMlKem768 mlkem768 = new TrackingMlKem768();
        private final TrackingHkdf hkdf = new TrackingHkdf();
        private final TrackingKeyWrap keyWrap = new TrackingKeyWrap();
        private final TrackingComparator comparator = new TrackingComparator();
        private final List<XHandle> xHandles = new ArrayList<>();
        private final List<PqHandle> pqHandles = new ArrayList<>();
        private final List<ObfuscationHybridRecipientPrivateKeys> pairs = new ArrayList<>();

        private ObfuscationHybridRecipientPrivateKeys pair(int xMarker, int pqMarker) {
            XHandle x = XHandle.returning(filled(32, xMarker));
            PqHandle pq = PqHandle.returning(filled(1184, pqMarker));
            xHandles.add(x);
            pqHandles.add(pq);
            ObfuscationHybridRecipientPrivateKeys pair =
                    new ObfuscationHybridRecipientPrivateKeys(x, pq);
            pairs.add(pair);
            return pair;
        }

        private ObfuscationHybridKeyDeriver deriver() {
            return new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);
        }

        private ObfuscationHybridCekRecovery recovery() {
            return new ObfuscationHybridCekRecovery(deriver(), keyWrap, comparator);
        }

        private List<ObfuscationHybridRecipientPrivateKeys> pairs() {
            return new ArrayList<>(pairs);
        }

        private void assertBorrowedHandlesOpen() {
            xHandles.forEach(handle -> assertEquals(0, handle.closeCalls));
            pqHandles.forEach(handle -> assertEquals(0, handle.closeCalls));
        }

        private void assertSensitiveReferencesCleared() {
            xHandles.forEach(handle -> handle.returnedSnapshots.forEach(value ->
                    assertTrue(allZero(value), "X25519 public snapshot must clear")));
            pqHandles.forEach(handle -> handle.returnedSnapshots.forEach(value ->
                    assertTrue(allZero(value), "ML-KEM public snapshot must clear")));
            x25519.providerOutputs.forEach(value ->
                    assertTrue(allZero(value), "X25519 secret must clear"));
            mlkem768.providerOutputs.forEach(value ->
                    assertTrue(allZero(value), "ML-KEM secret must clear"));
            hkdf.providerOutputs.forEach(value ->
                    assertTrue(allZero(value), "HKDF output must clear"));
            comparator.candidateReferences.forEach(value ->
                    assertTrue(allZero(value), "candidate rid must clear"));
            comparator.wireReferences.forEach(value ->
                    assertTrue(allZero(value), "wire rid must clear"));
            if (keyWrap.kekReference != null) {
                assertTrue(allZero(keyWrap.kekReference), "selected KEK must clear");
            }
            if (keyWrap.wrappedReference != null) {
                assertTrue(allZero(keyWrap.wrappedReference), "wrapped snapshot must clear");
            }
            if (keyWrap.providerResult != null) {
                assertTrue(allZero(keyWrap.providerResult), "provider CEK must clear");
            }
        }
    }

    private static final class XHandle implements X25519PrivateKeyHandle {
        private final byte[] publicKey;
        private final RuntimeException failure;
        private final List<byte[]> returnedSnapshots = new ArrayList<>();
        private int publicKeyCalls;
        private int closeCalls;

        private XHandle(byte[] publicKey, RuntimeException failure) {
            this.publicKey = publicKey == null ? null : publicKey.clone();
            this.failure = failure;
        }

        private static XHandle returning(byte[] publicKey) {
            return new XHandle(publicKey, null);
        }

        private int marker() {
            return Byte.toUnsignedInt(publicKey[0]);
        }

        @Override
        public byte[] publicKey() {
            publicKeyCalls++;
            if (failure != null) {
                throw failure;
            }
            if (publicKey == null) {
                return null;
            }
            byte[] result = publicKey.clone();
            returnedSnapshots.add(result);
            return result;
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class PqHandle implements MLKem768PrivateKeyHandle {
        private final byte[] publicKey;
        private final RuntimeException failure;
        private final List<byte[]> returnedSnapshots = new ArrayList<>();
        private int publicKeyCalls;
        private int closeCalls;

        private PqHandle(byte[] publicKey, RuntimeException failure) {
            this.publicKey = publicKey == null ? null : publicKey.clone();
            this.failure = failure;
        }

        private static PqHandle returning(byte[] publicKey) {
            return new PqHandle(publicKey, null);
        }

        private static PqHandle throwing(RuntimeException failure) {
            return new PqHandle(new byte[1184], failure);
        }

        private int marker() {
            return Byte.toUnsignedInt(publicKey[0]);
        }

        @Override
        public byte[] publicKey() {
            publicKeyCalls++;
            if (failure != null) {
                throw failure;
            }
            if (publicKey == null) {
                return null;
            }
            byte[] result = publicKey.clone();
            returnedSnapshots.add(result);
            return result;
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class TrackingX25519 implements X25519Crypto {
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private RuntimeException failure;
        private int failAtCall = -1;
        private int deriveCalls;

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
            deriveCalls++;
            if (failure != null && (failAtCall == 0 || deriveCalls == failAtCall)) {
                throw failure;
            }
            if (!(privateKey instanceof XHandle handle)) {
                throw new IllegalArgumentException("foreign X25519 handle");
            }
            byte[] result = filled(32, handle.marker());
            providerOutputs.add(result);
            return result;
        }
    }

    private static final class TrackingMlKem768 implements MLKem768Crypto {
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private final List<String> order = new ArrayList<>();
        private RuntimeException failure;
        private int failAtCall = -1;
        private int decapsulationCalls;

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
            throw new AssertionError("encapsulate must not be called");
        }

        @Override
        public byte[] decapsulate(MLKem768PrivateKeyHandle privateKey, byte[] ciphertext) {
            decapsulationCalls++;
            if (!(privateKey instanceof PqHandle handle)) {
                throw new IllegalArgumentException("foreign ML-KEM handle");
            }
            int ekMarker = Byte.toUnsignedInt(ciphertext[0]);
            order.add(ekMarker + ":" + handle.marker());
            if (failure != null && decapsulationCalls == failAtCall) {
                throw failure;
            }
            byte[] result = filled(32, handle.marker() + ekMarker);
            providerOutputs.add(result);
            return result;
        }
    }

    private static final class TrackingHkdf implements HkdfCrypto {
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private byte[] constantRid;
        private RuntimeException failure;
        private int calls;

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
            if (failure != null) {
                throw failure;
            }
            int marker = (Byte.toUnsignedInt(ikm[0])
                    + Byte.toUnsignedInt(ikm[32])) & 0xff;
            byte[] result = length == 16
                    ? constantRid == null ? filled(16, marker) : constantRid.clone()
                    : filled(32, marker + 0x40);
            providerOutputs.add(result);
            return result;
        }
    }

    private static final class TrackingComparator implements BiPredicate<byte[], byte[]> {
        private final List<byte[]> candidateReferences = new ArrayList<>();
        private final List<byte[]> wireReferences = new ArrayList<>();
        private int comparisons;

        @Override
        public boolean test(byte[] candidate, byte[] wireRid) {
            comparisons++;
            candidateReferences.add(candidate);
            wireReferences.add(wireRid);
            return MessageDigest.isEqual(candidate, wireRid);
        }
    }

    private static final class TrackingKeyWrap implements A256KeyWrapCrypto {
        private Object outcome;
        private RuntimeException failure;
        private byte[] kekReference;
        private byte[] wrappedReference;
        private byte[] kekSnapshot;
        private byte[] wrappedSnapshot;
        private byte[] providerResult;
        private int unwrapCalls;

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            throw new AssertionError("wrap must not be called");
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            unwrapCalls++;
            kekReference = kek;
            wrappedReference = wrappedKey;
            kekSnapshot = kek.clone();
            wrappedSnapshot = wrappedKey.clone();
            if (failure != null) {
                throw failure;
            }
            if (outcome == NullOutcome.INSTANCE) {
                return null;
            }
            providerResult = outcome instanceof byte[] value
                    ? value
                    : filled(32, Byte.toUnsignedInt(wrappedKey[0]));
            return providerResult;
        }
    }
}
