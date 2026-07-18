package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridKidRouterTest {

    @Test
    void routesOnlyAnExactLocalPairAndRejectsAnUnrelatedPair() {
        LocalPair first = pair(0x11, 0x21);
        LocalPair unrelated = pair(0x12, 0x22);
        PublicRecipient firstWireEntry = recipient(first.xKid(), first.pqKid());
        List<RecipientEntry> wireEntries = List.of(
                firstWireEntry,
                recipient(unrelated.xKid(), unrelated.pqKid())
        );
        PublicHybridKidRouter router = new PublicHybridKidRouter();

        PublicHybridKidRouter.Match match = router.route(wireEntries, List.of(first.keys()));

        assertSame(firstWireEntry, match.recipient());
        assertSame(first.x25519(), match.x25519PrivateKey());
        assertSame(first.mlkem768(), match.mlkem768PrivateKey());
        assertCode(
                ErrorCode.NOT_FOR_ME,
                () -> router.route(List.of(firstWireEntry), List.of(unrelated.keys()))
        );
        assertEquals(32, first.x25519().publicKey().length);
        assertEquals(1184, first.mlkem768().publicKey().length);
    }

    @Test
    void routesExactPairAtMiddleAndLastPositions() {
        LocalPair local = pair(0x11, 0x21);
        LocalPair unrelated = pair(0x12, 0x22);
        PublicRecipient middle = recipient(local.xKid(), local.pqKid());
        PublicRecipient last = recipient(local.xKid(), local.pqKid());

        assertSame(middle, new PublicHybridKidRouter().route(
                List.of(
                        recipient(unrelated.xKid(), unrelated.pqKid()),
                        middle,
                        recipient(unrelated.xKid(), local.pqKid())
                ),
                List.of(local.keys())
        ).recipient());
        assertSame(last, new PublicHybridKidRouter().route(
                List.of(
                        recipient(unrelated.xKid(), unrelated.pqKid()),
                        recipient(local.xKid(), unrelated.pqKid()),
                        last
                ),
                List.of(local.keys())
        ).recipient());
        assertEquals(32, local.x25519().publicKey().length);
        assertEquals(1184, local.mlkem768().publicKey().length);
    }

    @Test
    void xOnlyPqOnlyAndCrossedLocalComponentsNeverMatch() {
        LocalPair first = pair(0x11, 0x21);
        LocalPair second = pair(0x12, 0x22);
        PublicHybridKidRouter router = new PublicHybridKidRouter();

        assertCode(ErrorCode.NOT_FOR_ME, () -> router.route(
                List.of(recipient(first.xKid(), second.pqKid())),
                List.of(first.keys())
        ));
        assertCode(ErrorCode.NOT_FOR_ME, () -> router.route(
                List.of(recipient(second.xKid(), first.pqKid())),
                List.of(first.keys())
        ));
        assertCode(ErrorCode.NOT_FOR_ME, () -> router.route(
                List.of(recipient(first.xKid(), second.pqKid())),
                List.of(first.keys(), second.keys())
        ));
        assertEquals(32, first.x25519().publicKey().length);
        assertEquals(1184, second.mlkem768().publicKey().length);
    }

    @Test
    void rejectsDuplicateLocalPairButAllowsEitherSingleComponentToRepeat() {
        byte[] xFirst = marked(32, 0x11);
        byte[] pqFirst = marked(1184, 0x21);
        LocalPair first = pair(xFirst, pqFirst);
        LocalPair duplicate = pair(xFirst, pqFirst);
        LocalPair sameX = pair(xFirst, marked(1184, 0x22));
        LocalPair samePq = pair(marked(32, 0x12), pqFirst);
        PublicHybridKidRouter router = new PublicHybridKidRouter();

        assertCode(ErrorCode.INVALID_FIELD, () -> router.route(
                List.of(recipient(first.xKid(), first.pqKid())),
                List.of(first.keys(), duplicate.keys())
        ));
        assertCode(ErrorCode.INVALID_FIELD, () -> router.route(
                List.of(recipient(first.xKid(), first.pqKid())),
                Arrays.asList(first.keys(), (PublicHybridRecipientPrivateKeys) null)
        ));

        PublicRecipient sameXWire = recipient(sameX.xKid(), sameX.pqKid());
        PublicRecipient samePqWire = recipient(samePq.xKid(), samePq.pqKid());
        assertSame(sameXWire, router.route(
                List.of(sameXWire), List.of(first.keys(), sameX.keys())
        ).recipient());
        assertSame(samePqWire, router.route(
                List.of(samePqWire), List.of(first.keys(), samePq.keys())
        ).recipient());
        assertEquals(32, first.x25519().publicKey().length);
        assertEquals(1184, duplicate.mlkem768().publicKey().length);
    }

    @Test
    void validatesHybridWireStructureAndDuplicateRulesAcrossTheFullScan() {
        LocalPair first = pair(0x11, 0x21);
        LocalPair second = pair(0x12, 0x22);
        LocalPair unrelated = pair(0x13, 0x23);
        PublicRecipient firstWire = recipient(first.xKid(), first.pqKid());
        PublicRecipient secondWire = recipient(second.xKid(), second.pqKid());
        PublicRecipient unrelatedWire = recipient(unrelated.xKid(), unrelated.pqKid());
        PublicHybridKidRouter router = new PublicHybridKidRouter();

        PublicRecipient missingPq = new PublicRecipient(
                new RecipientKid(first.xKid(), null), new byte[40], null
        );
        assertCode(ErrorCode.INVALID_FIELD,
                () -> router.route(List.of(missingPq), List.of(first.keys())));
        assertCode(ErrorCode.INVALID_FIELD, () -> router.route(
                List.of(firstWire, recipient(first.xKid(), first.pqKid())),
                List.of(first.keys())
        ));

        PublicHybridKidRouter.Match selected = router.route(
                List.of(
                        unrelatedWire,
                        recipient(unrelated.xKid(), unrelated.pqKid()),
                        new ObfuscationRecipient(new byte[16], new byte[40], new byte[1088]),
                        secondWire,
                        firstWire
                ),
                List.of(first.keys(), second.keys())
        );
        assertSame(secondWire, selected.recipient());
        assertSame(second.x25519(), selected.x25519PrivateKey());

        assertCode(ErrorCode.INVALID_FIELD, () -> router.route(
                List.of(firstWire, secondWire, recipient(first.xKid(), first.pqKid())),
                List.of(first.keys(), second.keys())
        ));
        assertEquals(32, first.x25519().publicKey().length);
        assertEquals(1184, second.mlkem768().publicKey().length);
    }

    @Test
    void mapsEveryLocalAccessorContractFailureToInternalAndClearsSnapshots() {
        RuntimeException xFailure = new IllegalStateException("x accessor failed");
        ConfigurableX25519Handle throwingX = new ConfigurableX25519Handle(null, xFailure);
        ConfigurableMlKem768Handle validPq = new ConfigurableMlKem768Handle(
                marked(1184, 0x21), null
        );
        assertInternal(
                new PublicHybridRecipientPrivateKeys(throwingX, validPq),
                xFailure
        );

        for (byte[] malformedX : new byte[][]{null, new byte[31], new byte[33]}) {
            ConfigurableX25519Handle x = new ConfigurableX25519Handle(malformedX, null);
            ConfigurableMlKem768Handle pq = new ConfigurableMlKem768Handle(
                    marked(1184, 0x21), null
            );
            ProtocolException failure = assertInternal(
                    new PublicHybridRecipientPrivateKeys(x, pq),
                    null
            );
            assertTrue(failure.getCause() instanceof IllegalStateException);
            if (x.lastSnapshot != null) {
                assertTrue(allZero(x.lastSnapshot));
            }
            assertFalse(x.closed);
            assertFalse(pq.closed);
        }

        RuntimeException pqFailure = new IllegalStateException("pq accessor failed");
        ConfigurableX25519Handle validX = new ConfigurableX25519Handle(marked(32, 0x11), null);
        ConfigurableMlKem768Handle throwingPq = new ConfigurableMlKem768Handle(null, pqFailure);
        assertInternal(
                new PublicHybridRecipientPrivateKeys(validX, throwingPq),
                pqFailure
        );
        assertTrue(allZero(validX.lastSnapshot));

        for (byte[] malformedPq : new byte[][]{null, new byte[1183], new byte[1185]}) {
            ConfigurableX25519Handle x = new ConfigurableX25519Handle(marked(32, 0x11), null);
            ConfigurableMlKem768Handle pq = new ConfigurableMlKem768Handle(malformedPq, null);
            ProtocolException failure = assertInternal(
                    new PublicHybridRecipientPrivateKeys(x, pq),
                    null
            );
            assertTrue(failure.getCause() instanceof IllegalStateException);
            assertTrue(allZero(x.lastSnapshot));
            if (pq.lastSnapshot != null) {
                assertTrue(allZero(pq.lastSnapshot));
            }
            assertFalse(x.closed);
            assertFalse(pq.closed);
        }
    }

    @Test
    void validatesTopLevelPairAndMatchContracts() {
        LocalPair local = pair(0x11, 0x21);
        PublicRecipient recipient = recipient(local.xKid(), local.pqKid());
        PublicHybridKidRouter router = new PublicHybridKidRouter();

        assertThrows(IllegalArgumentException.class, () -> router.route(null, List.of()));
        assertThrows(IllegalArgumentException.class, () -> router.route(List.of(), null));
        assertCode(ErrorCode.NOT_FOR_ME, () -> router.route(List.of(recipient), List.of()));
        assertCode(ErrorCode.NOT_FOR_ME, () -> router.route(List.of(), List.of(local.keys())));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientPrivateKeys(null, local.mlkem768()));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridRecipientPrivateKeys(local.x25519(), null));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKidRouter.Match(null, local.x25519(), local.mlkem768()));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKidRouter.Match(recipient, null, local.mlkem768()));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicHybridKidRouter.Match(recipient, local.x25519(), null));
        assertEquals(32, local.x25519().publicKey().length);
        assertEquals(1184, local.mlkem768().publicKey().length);
    }

    private static ProtocolException assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        return failure;
    }

    private static ProtocolException assertInternal(
            PublicHybridRecipientPrivateKeys privateKeys,
            RuntimeException expectedCause
    ) {
        ProtocolException failure = assertCode(
                ErrorCode.INTERNAL_ERROR,
                () -> new PublicHybridKidRouter().route(List.of(), List.of(privateKeys))
        );
        assertEquals("failed to inspect local hybrid key handles", failure.getMessage());
        assertNotNull(failure.getCause());
        if (expectedCause != null) {
            assertSame(expectedCause, failure.getCause());
        }
        return failure;
    }

    private static PublicRecipient recipient(String x25519Kid, String mlkem768Kid) {
        return new PublicRecipient(
                new RecipientKid(x25519Kid, mlkem768Kid),
                new byte[40],
                new byte[1088]
        );
    }

    private static LocalPair pair(int xMarker, int pqMarker) {
        return pair(marked(32, xMarker), marked(1184, pqMarker));
    }

    private static LocalPair pair(byte[] xPublic, byte[] pqPublic) {
        TrackingX25519Handle x25519 = new TrackingX25519Handle(xPublic);
        TrackingMlKem768Handle mlkem768 = new TrackingMlKem768Handle(pqPublic);
        return new LocalPair(
                x25519,
                mlkem768,
                X25519KeyId.derive(xPublic),
                MLKem768KeyId.derive(pqPublic)
        );
    }

    private static byte[] marked(int length, int marker) {
        byte[] value = new byte[length];
        value[0] = (byte) marker;
        return value;
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private record LocalPair(
            TrackingX25519Handle x25519,
            TrackingMlKem768Handle mlkem768,
            String xKid,
            String pqKid
    ) {
        private PublicHybridRecipientPrivateKeys keys() {
            return new PublicHybridRecipientPrivateKeys(x25519, mlkem768);
        }
    }

    private static final class TrackingX25519Handle implements X25519PrivateKeyHandle {
        private final byte[] publicKey;
        private boolean closed;

        private TrackingX25519Handle(byte[] publicKey) {
            this.publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKey() {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            return publicKey.clone();
        }

        @Override
        public void close() {
            closed = true;
            Arrays.fill(publicKey, (byte) 0);
        }
    }

    private static final class TrackingMlKem768Handle implements MLKem768PrivateKeyHandle {
        private final byte[] publicKey;
        private boolean closed;

        private TrackingMlKem768Handle(byte[] publicKey) {
            this.publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKey() {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            return publicKey.clone();
        }

        @Override
        public void close() {
            closed = true;
            Arrays.fill(publicKey, (byte) 0);
        }
    }

    private static final class ConfigurableX25519Handle implements X25519PrivateKeyHandle {
        private final byte[] publicKey;
        private final RuntimeException failure;
        private byte[] lastSnapshot;
        private boolean closed;

        private ConfigurableX25519Handle(byte[] publicKey, RuntimeException failure) {
            this.publicKey = publicKey == null ? null : publicKey.clone();
            this.failure = failure;
        }

        @Override
        public byte[] publicKey() {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            if (failure != null) {
                throw failure;
            }
            lastSnapshot = publicKey == null ? null : publicKey.clone();
            return lastSnapshot;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    private static final class ConfigurableMlKem768Handle implements MLKem768PrivateKeyHandle {
        private final byte[] publicKey;
        private final RuntimeException failure;
        private byte[] lastSnapshot;
        private boolean closed;

        private ConfigurableMlKem768Handle(byte[] publicKey, RuntimeException failure) {
            this.publicKey = publicKey == null ? null : publicKey.clone();
            this.failure = failure;
        }

        @Override
        public byte[] publicKey() {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            if (failure != null) {
                throw failure;
            }
            lastSnapshot = publicKey == null ? null : publicKey.clone();
            return lastSnapshot;
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
