package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.recipient.ObfuscationX25519RecipientBuilder;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
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

class ObfuscationX25519CekRecoveryTest {

    private static final Epk VALID_EPK = new Epk("OKP", "X25519", filled(32, 0x6a));

    @Test
    void realBcBuilderWireRecoversForEveryRecipientAndRejectsEmptyOrUnrelatedKeys() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        List<X25519PrivateKeyHandle> recipients = List.of(
                x25519.generatePrivateKey(),
                x25519.generatePrivateKey(),
                x25519.generatePrivateKey()
        );
        X25519PrivateKeyHandle unrelated = x25519.generatePrivateKey();
        byte[] cek = sequence(32, 0x20);
        List<byte[]> publicKeys = recipients.stream().map(X25519PrivateKeyHandle::publicKey).toList();
        try {
            ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
                    new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap)
                            .build(publicKeys, cek);
            ObfuscationX25519CekRecovery recovery = new ObfuscationX25519CekRecovery(
                    new ObfuscationX25519KeyDeriver(x25519, hkdf), keyWrap);

            assertEquals(8, prepared.recipients().size());
            for (X25519PrivateKeyHandle recipient : recipients) {
                assertArrayEquals(cek, recovery.recover(
                        prepared.epk(), prepared.recipients(), List.of(recipient)));
                assertEquals(32, recipient.publicKey().length, "borrowed handle must remain open");
            }
            assertCode(ErrorCode.NOT_FOR_ME,
                    () -> recovery.recover(prepared.epk(), prepared.recipients(), List.of()));
            assertCode(ErrorCode.NOT_FOR_ME,
                    () -> recovery.recover(prepared.epk(), prepared.recipients(), List.of(unrelated)));
            assertEquals(32, unrelated.publicKey().length);
        } finally {
            publicKeys.forEach(ObfuscationX25519CekRecoveryTest::clear);
            recipients.forEach(X25519PrivateKeyHandle::close);
            unrelated.close();
            clear(cek);
        }
    }

    @Test
    void firstMiddleAndLastMatchesStillScanEveryCandidateAgainstEveryWireRid() {
        for (int wireIndex : List.of(0, 3, 7)) {
            Fixture fixture = new Fixture();
            TrackingHandle first = fixture.handle(0x11);
            TrackingHandle match = fixture.handle(0x22);
            List<RecipientEntry> wire = recipientsWithRidAt(wireIndex, 0x22);

            byte[] recovered = fixture.recovery().recover(
                    VALID_EPK, wire, List.of(first, match));

            assertEquals(16, fixture.comparator.comparisons);
            assertEquals(2, fixture.x25519.deriveCalls);
            assertEquals(1, fixture.keyWrap.unwrapCalls);
            assertEquals(0x50 + wireIndex, Byte.toUnsignedInt(recovered[0]));
            fixture.assertAllSensitiveArgumentsCleared();
            assertEquals(0, first.closeCalls);
            assertEquals(0, match.closeCalls);
            clear(recovered);
        }
    }

    @Test
    void selectsSmallestWireIndexEvenWhenLocalKeysAreInReverseOrder() {
        Fixture fixture = new Fixture();
        TrackingHandle localForLaterWire = fixture.handle(0x11);
        TrackingHandle localForFirstWire = fixture.handle(0x22);
        List<RecipientEntry> wire = uniqueRecipients();
        wire.set(0, recipient(0x22, 0x61));
        wire.set(5, recipient(0x11, 0x66));

        byte[] recovered = fixture.recovery().recover(
                VALID_EPK, wire, List.of(localForLaterWire, localForFirstWire));

        assertEquals(0x61, Byte.toUnsignedInt(recovered[0]));
        assertEquals(0x22 + 0x40, Byte.toUnsignedInt(fixture.keyWrap.kekSnapshot[0]));
        assertEquals(16, fixture.comparator.comparisons);
        assertEquals(2, fixture.x25519.deriveCalls);
        assertEquals(1, fixture.keyWrap.unwrapCalls);
        fixture.assertAllSensitiveArgumentsCleared();
        clear(recovered);
    }

    @Test
    void ridCollisionAtSameWireIndexSelectsSmallestLocalInputIndex() {
        Fixture fixture = new Fixture();
        fixture.hkdf.constantRid = filled(16, 0x44);
        TrackingHandle first = fixture.handle(0x11);
        TrackingHandle second = fixture.handle(0x22);
        List<RecipientEntry> wire = uniqueRecipients();
        wire.set(2, recipient(0x44, 0x63));

        byte[] recovered = fixture.recovery().recover(VALID_EPK, wire, List.of(first, second));

        assertEquals(0x11 + 0x40, Byte.toUnsignedInt(fixture.keyWrap.kekSnapshot[0]));
        assertEquals(16, fixture.comparator.comparisons);
        assertEquals(2, fixture.x25519.deriveCalls);
        assertEquals(1, fixture.keyWrap.unwrapCalls);
        fixture.assertAllSensitiveArgumentsCleared();
        clear(recovered);
        clear(fixture.hkdf.constantRid);
    }

    @Test
    void duplicateWireRidIsInvalidBeforeAnyLocalHandleIsRead() {
        Fixture fixture = new Fixture();
        TrackingHandle local = fixture.handle(0x11);
        List<RecipientEntry> wire = uniqueRecipients();
        wire.set(7, recipient(0x70, 0x77));
        wire.set(3, recipient(0x70, 0x73));

        ProtocolException failure = assertCode(
                ErrorCode.INVALID_FIELD,
                () -> fixture.recovery().recover(VALID_EPK, wire, List.of(local)));

        assertTrue(failure.getMessage().contains("duplicate"));
        assertEquals(0, local.publicKeyCalls);
        assertEquals(0, fixture.x25519.deriveCalls);
        assertEquals(0, fixture.comparator.comparisons);
        assertEquals(0, fixture.keyWrap.unwrapCalls);
    }

    @Test
    void duplicateLocalPublicKeyIsInternalAndNeverDerives() {
        Fixture fixture = new Fixture();
        TrackingHandle first = fixture.handle(0x11);
        TrackingHandle duplicate = fixture.handle(0x11);

        ProtocolException failure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> fixture.recovery().recover(
                        VALID_EPK, uniqueRecipients(), List.of(first, duplicate)));

        assertNull(failure.getCause());
        assertEquals(0, fixture.x25519.deriveCalls);
        assertEquals(0, fixture.comparator.comparisons);
        fixture.assertPublicSnapshotsCleared();
        assertEquals(0, first.closeCalls);
        assertEquals(0, duplicate.closeCalls);
    }

    @Test
    void selectedEntryIsUnwrappedExactlyOnceAndFailureNeverFallsBack() {
        Fixture fixture = new Fixture();
        TrackingHandle firstLocal = fixture.handle(0x11);
        TrackingHandle secondLocal = fixture.handle(0x22);
        List<RecipientEntry> wire = uniqueRecipients();
        wire.set(0, recipient(0x22, 0x61));
        wire.set(1, recipient(0x11, 0x62));
        CryptoOperationException integrity = new CryptoOperationException("integrity");
        fixture.keyWrap.failure = integrity;

        assertAttackerFailure(() -> fixture.recovery().recover(
                VALID_EPK, wire, List.of(firstLocal, secondLocal)));

        assertEquals(16, fixture.comparator.comparisons);
        assertEquals(1, fixture.keyWrap.unwrapCalls);
        assertEquals(0x61, Byte.toUnsignedInt(fixture.keyWrap.wrappedSnapshot[0]));
        fixture.assertAllSensitiveArgumentsCleared();
    }

    @Test
    void realBcLowOrderEpkHasUniformAttackerVisibleFailure() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        X25519PrivateKeyHandle local = x25519.generatePrivateKey();
        try {
            ObfuscationX25519CekRecovery recovery = new ObfuscationX25519CekRecovery(
                    new ObfuscationX25519KeyDeriver(x25519, new BouncyCastleHkdfCrypto()),
                    new BouncyCastleA256KeyWrapCrypto());

            assertAttackerFailure(() -> recovery.recover(
                    new Epk("OKP", "X25519", new byte[32]),
                    uniqueRecipients(),
                    List.of(local)));
            assertEquals(32, local.publicKey().length);
        } finally {
            local.close();
        }
    }

    @Test
    void x25519AndKeyWrapCryptoFailuresHaveTheSameAttackerVisibleShape() {
        Fixture deriveFailure = new Fixture();
        deriveFailure.handle(0x11);
        deriveFailure.x25519.failure = new CryptoOperationException("peer was low order");
        assertAttackerFailure(() -> deriveFailure.recovery().recover(
                VALID_EPK, uniqueRecipients(), List.of(deriveFailure.handles.get(0))));
        deriveFailure.assertPublicSnapshotsCleared();

        for (Object outcome : List.of(
                new CryptoOperationException("integrity"),
                NullOutcome.INSTANCE,
                new byte[31],
                new byte[33])) {
            Fixture unwrapFailure = matchingFixture();
            unwrapFailure.keyWrap.outcome = outcome;
            assertAttackerFailure(() -> unwrapFailure.recovery().recover(
                    VALID_EPK, recipientsWithRidAt(4, 0x11), unwrapFailure.keys()));
            assertEquals(1, unwrapFailure.keyWrap.unwrapCalls);
            unwrapFailure.assertAllSensitiveArgumentsCleared();
        }
    }

    @Test
    void malformedLocalHandlesAreInternalAndBorrowedHandlesStayOpen() {
        List<TrackingHandle> invalid = List.of(
                TrackingHandle.returning(null),
                TrackingHandle.returning(new byte[31]),
                TrackingHandle.returning(new byte[33]),
                TrackingHandle.throwing(new IllegalStateException("closed"))
        );
        for (TrackingHandle handle : invalid) {
            Fixture fixture = new Fixture();
            fixture.handles.add(handle);
            ProtocolException failure = assertCode(
                    ErrorCode.INTERNAL_ERROR,
                    () -> fixture.recovery().recover(
                            VALID_EPK, uniqueRecipients(), List.of(handle)));
            if (handle.failure != null) {
                assertSame(handle.failure, failure.getCause());
            }
            assertEquals(0, handle.closeCalls);
            fixture.assertPublicSnapshotsCleared();
        }

        Fixture nullHandle = new Fixture();
        List<X25519PrivateKeyHandle> keys = new ArrayList<>();
        keys.add(null);
        assertCode(ErrorCode.INTERNAL_ERROR,
                () -> nullHandle.recovery().recover(VALID_EPK, uniqueRecipients(), keys));
    }

    @Test
    void foreignHandleHkdfFailureAndNonCryptoUnwrapFailureRemainInternalWithCause() {
        Fixture foreignFixture = new Fixture();
        X25519PrivateKeyHandle foreign = new X25519PrivateKeyHandle() {
            @Override public byte[] publicKey() { return filled(32, 0x31); }
            @Override public void close() { }
        };
        ProtocolException foreignFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> foreignFixture.recovery().recover(
                        VALID_EPK, uniqueRecipients(), List.of(foreign)));
        assertTrue(foreignFailure.getCause() instanceof IllegalArgumentException);

        Fixture hkdfFixture = matchingFixture();
        CryptoOperationException hkdfCause = new CryptoOperationException("HKDF down");
        hkdfFixture.hkdf.failure = hkdfCause;
        ProtocolException hkdfFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> hkdfFixture.recovery().recover(
                        VALID_EPK, recipientsWithRidAt(0, 0x11), hkdfFixture.keys()));
        assertTrue(hkdfFailure.getCause() instanceof IllegalStateException);
        assertSame(hkdfCause, hkdfFailure.getCause().getCause());

        Fixture unwrapFixture = matchingFixture();
        IllegalStateException providerBug = new IllegalStateException("provider bug");
        unwrapFixture.keyWrap.failure = providerBug;
        ProtocolException unwrapFailure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> unwrapFixture.recovery().recover(
                        VALID_EPK, recipientsWithRidAt(0, 0x11), unwrapFixture.keys()));
        assertSame(providerBug, unwrapFailure.getCause());
        unwrapFixture.assertAllSensitiveArgumentsCleared();
    }

    @Test
    void malformedEpkAndWireEntriesAreInvalidFields() {
        Fixture fixture = new Fixture();
        TrackingHandle local = fixture.handle(0x11);
        List<Runnable> malformed = new ArrayList<>();
        malformed.add(() -> fixture.recovery().recover(null, uniqueRecipients(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                new Epk("EC", "X25519", new byte[32]), uniqueRecipients(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                new Epk("OKP", "X448", new byte[32]), uniqueRecipients(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                new Epk("OKP", "X25519", new byte[31]), uniqueRecipients(), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(VALID_EPK, null, List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, uniqueRecipients().subList(0, 7), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, replacing(0, new PublicRecipient(
                        new RecipientKid("kid", null), new byte[40], null)), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, replacing(0, new ObfuscationRecipient(
                        new byte[15], new byte[40], null)), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, replacing(0, new ObfuscationRecipient(
                        new byte[16], new byte[39], null)), List.of(local)));
        malformed.add(() -> fixture.recovery().recover(
                VALID_EPK, replacing(0, new ObfuscationRecipient(
                        new byte[16], new byte[40], new byte[1])), List.of(local)));

        malformed.forEach(operation -> assertCode(ErrorCode.INVALID_FIELD, operation));
    }

    @Test
    void notForMeAndFailureClearEveryCandidateAndSnapshotWithoutClosingHandles() {
        Fixture notForMe = new Fixture();
        TrackingHandle first = notForMe.handle(0x11);
        TrackingHandle second = notForMe.handle(0x22);
        assertCode(ErrorCode.NOT_FOR_ME,
                () -> notForMe.recovery().recover(
                        VALID_EPK, uniqueRecipients(), List.of(first, second)));
        assertEquals(16, notForMe.comparator.comparisons);
        notForMe.assertAllSensitiveArgumentsCleared();
        assertEquals(0, first.closeCalls);
        assertEquals(0, second.closeCalls);

        Fixture failure = new Fixture();
        TrackingHandle failureFirst = failure.handle(0x11);
        TrackingHandle failureSecond = failure.handle(0x22);
        failure.x25519.failAtCall = 2;
        failure.x25519.failure = new CryptoOperationException("failed second candidate");
        assertAttackerFailure(() -> failure.recovery().recover(
                VALID_EPK, uniqueRecipients(), List.of(failureFirst, failureSecond)));
        failure.assertAllSensitiveArgumentsCleared();
        assertEquals(0, failureFirst.closeCalls);
        assertEquals(0, failureSecond.closeCalls);
    }

    @Test
    void successReturnsCallerOwnedCopyAndClearsProviderResultAndInputs() {
        Fixture fixture = matchingFixture();
        byte[] recovered = fixture.recovery().recover(
                VALID_EPK, recipientsWithRidAt(0, 0x11), fixture.keys());
        byte[] providerResult = fixture.keyWrap.providerResult;

        assertNotSame(providerResult, recovered);
        assertTrue(allZero(providerResult));
        assertFalse(allZero(recovered));
        fixture.assertAllSensitiveArgumentsCleared();
        byte original = recovered[1];
        providerResult[1] = 0x7f;
        assertEquals(original, recovered[1]);
        clear(providerResult);
        clear(recovered);
    }

    private static Fixture matchingFixture() {
        Fixture fixture = new Fixture();
        fixture.handle(0x11);
        return fixture;
    }

    private static List<RecipientEntry> recipientsWithRidAt(int index, int ridMarker) {
        List<RecipientEntry> recipients = uniqueRecipients();
        recipients.set(index, recipient(ridMarker, 0x50 + index));
        return recipients;
    }

    private static List<RecipientEntry> uniqueRecipients() {
        List<RecipientEntry> recipients = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            recipients.add(recipient(0x70 + i, 0x50 + i));
        }
        return recipients;
    }

    private static List<RecipientEntry> replacing(int index, RecipientEntry entry) {
        List<RecipientEntry> recipients = uniqueRecipients();
        recipients.set(index, entry);
        return recipients;
    }

    private static ObfuscationRecipient recipient(int ridMarker, int encryptedKeyMarker) {
        return new ObfuscationRecipient(
                filled(16, ridMarker), filled(40, encryptedKeyMarker), null);
    }

    private static ProtocolException assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        return failure;
    }

    private static void assertAttackerFailure(Runnable operation) {
        ProtocolException failure = assertCode(ErrorCode.KEY_UNWRAP_FAILED, operation);
        assertEquals("obfuscation recipient key recovery failed", failure.getMessage());
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

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private enum NullOutcome { INSTANCE }

    private static final class Fixture {
        private final TrackingX25519 x25519 = new TrackingX25519();
        private final TrackingHkdf hkdf = new TrackingHkdf();
        private final TrackingKeyWrap keyWrap = new TrackingKeyWrap();
        private final TrackingComparator comparator = new TrackingComparator();
        private final List<TrackingHandle> handles = new ArrayList<>();

        private TrackingHandle handle(int marker) {
            TrackingHandle handle = TrackingHandle.returning(filled(32, marker));
            handles.add(handle);
            return handle;
        }

        private ObfuscationX25519CekRecovery recovery() {
            return new ObfuscationX25519CekRecovery(
                    new ObfuscationX25519KeyDeriver(x25519, hkdf),
                    keyWrap,
                    comparator);
        }

        private List<X25519PrivateKeyHandle> keys() {
            return new ArrayList<>(handles);
        }

        private void assertPublicSnapshotsCleared() {
            handles.forEach(handle -> handle.returnedSnapshots.forEach(
                    snapshot -> assertTrue(allZero(snapshot), "public-key snapshot must clear")));
        }

        private void assertAllSensitiveArgumentsCleared() {
            assertPublicSnapshotsCleared();
            x25519.providerOutputs.forEach(
                    output -> assertTrue(allZero(output), "shared secret must clear"));
            hkdf.providerOutputs.forEach(
                    output -> assertTrue(allZero(output), "HKDF provider output must clear"));
            comparator.candidateReferences.forEach(
                    rid -> assertTrue(allZero(rid), "candidate rid must clear"));
            comparator.wireReferences.forEach(
                    rid -> assertTrue(allZero(rid), "wire rid snapshot must clear"));
            if (keyWrap.kekReference != null) {
                assertTrue(allZero(keyWrap.kekReference), "unwrap KEK must clear");
            }
            if (keyWrap.wrappedReference != null) {
                assertTrue(allZero(keyWrap.wrappedReference), "wrapped-key snapshot must clear");
            }
            if (keyWrap.providerResult != null) {
                assertTrue(allZero(keyWrap.providerResult), "provider CEK must clear");
            }
        }
    }

    private static final class TrackingHandle implements X25519PrivateKeyHandle {
        private final byte[] publicKey;
        private final RuntimeException failure;
        private final List<byte[]> returnedSnapshots = new ArrayList<>();
        private int publicKeyCalls;
        private int closeCalls;

        private TrackingHandle(byte[] publicKey, RuntimeException failure) {
            this.publicKey = publicKey == null ? null : publicKey.clone();
            this.failure = failure;
        }

        private static TrackingHandle returning(byte[] publicKey) {
            return new TrackingHandle(publicKey, null);
        }

        private static TrackingHandle throwing(RuntimeException failure) {
            return new TrackingHandle(new byte[32], failure);
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
            byte[] snapshot = publicKey.clone();
            returnedSnapshots.add(snapshot);
            return snapshot;
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class TrackingX25519 implements X25519Crypto {
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private RuntimeException failure;
        private int failAtCall = 1;
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
            if (failure != null && deriveCalls == failAtCall) {
                throw failure;
            }
            if (!(privateKey instanceof TrackingHandle handle)) {
                throw new IllegalArgumentException("foreign handle");
            }
            byte[] shared = filled(32, handle.marker());
            providerOutputs.add(shared);
            return shared;
        }
    }

    private static final class TrackingHkdf implements HkdfCrypto {
        private final List<byte[]> providerOutputs = new ArrayList<>();
        private byte[] constantRid;
        private RuntimeException failure;

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
            if (failure != null) {
                throw failure;
            }
            int marker = Byte.toUnsignedInt(ikm[0]);
            byte[] output = length == 16
                    ? (constantRid == null ? filled(16, marker) : constantRid.clone())
                    : filled(32, marker + 0x40);
            providerOutputs.add(output);
            return output;
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
            if (outcome instanceof RuntimeException exception) {
                throw exception;
            }
            if (outcome == NullOutcome.INSTANCE) {
                return null;
            }
            providerResult = outcome instanceof byte[] bytes
                    ? bytes
                    : filled(32, Byte.toUnsignedInt(wrappedKey[0]));
            return providerResult;
        }
    }
}
