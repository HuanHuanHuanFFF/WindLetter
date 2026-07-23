package com.windletter.protocol.key;

import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObfuscationHybridKeyDeriverTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void realSenderAndReceiverDeriveSameRidAndKekFromOneEntry() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                x25519,
                mlkem768,
                new BouncyCastleHkdfCrypto()
        );

        try (X25519PrivateKeyHandle ephemeral = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipientX25519 = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle recipientMlkem = mlkem768.generatePrivateKey()) {
            byte[] ephemeralPublic = ephemeral.publicKey();
            byte[] recipientX25519Public = recipientX25519.publicKey();
            byte[] recipientMlkemPublic = recipientMlkem.publicKey();
            try (ObfuscationHybridKeyDeriver.SenderMaterial sender =
                         deriver.deriveForSender(
                                 ephemeral,
                                 recipientX25519Public,
                                 recipientMlkemPublic
                         );
                 ObfuscationHybridKeyDeriver.ReceiverContext receiverContext =
                         deriver.openForReceiver(
                                 recipientX25519,
                                 recipientMlkem,
                                 ephemeralPublic
                         );
                 ObfuscationHybridKeyDeriver.DerivedMaterial receiver =
                         receiverContext.deriveEntry(sender.ek())) {
                byte[] senderRid = sender.rid();
                byte[] senderKek = sender.kek();
                byte[] receiverRid = receiver.rid();
                byte[] receiverKek = receiver.kek();
                try {
                    assertFalse(receiverContext.candidateCryptoFailed());
                    assertFalse(receiver.candidateCryptoFailed());
                    assertArrayEquals(senderRid, receiverRid);
                    assertArrayEquals(senderKek, receiverKek);
                } finally {
                    clear(senderRid);
                    clear(senderKek);
                    clear(receiverRid);
                    clear(receiverKek);
                }
            } finally {
                clear(ephemeralPublic);
                clear(recipientX25519Public);
                clear(recipientMlkemPublic);
            }
        }
    }

    @Test
    void givesEachHkdfCallAnIndependentCopyOfTheOriginalCombinedSecret() {
        byte[] ssEcc = sequence(0x00, 32);
        byte[] ssPq = sequence(0x20, 32);
        byte[] expectedZ = sequence(0x00, 64);
        MutatingHkdfCrypto hkdf = new MutatingHkdfCrypto();
        MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(
                filled(1088, (byte) 0x55),
                ssPq
        );
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                new FixedMlKem768Crypto(encapsulation),
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.SenderMaterial ignored =
                     deriver.deriveForSender(
                             new TrackingX25519Handle(),
                             filled(32, (byte) 0x33),
                             filled(1184, (byte) 0x44)
                     )) {
            assertEquals(2, hkdf.ikmSnapshots.size());
            assertArrayEquals(expectedZ, hkdf.ikmSnapshots.get(0));
            assertArrayEquals(expectedZ, hkdf.ikmSnapshots.get(1));
            assertTrue(allZero(hkdf.ikmArguments.get(0)));
            assertTrue(allZero(hkdf.ikmArguments.get(1)));
        } finally {
            clear(ssEcc);
            clear(ssPq);
            clear(expectedZ);
            encapsulation.close();
        }
    }

    @Test
    void derivesFixedRidAndKekFromEccThenPq() {
        byte[] ssEcc = sequence(0x00, 32);
        byte[] ssPqInput = sequence(0x20, 32);
        MLKem768Encapsulation encapsulation = new MLKem768Encapsulation(
                filled(1088, (byte) 0x5a),
                ssPqInput
        );
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                new FixedMlKem768Crypto(encapsulation),
                new BouncyCastleHkdfCrypto()
        );

        try (ObfuscationHybridKeyDeriver.SenderMaterial material =
                     deriver.deriveForSender(
                             new TrackingX25519Handle(),
                             filled(32, (byte) 0x11),
                             filled(1184, (byte) 0x22)
                     )) {
            byte[] rid = material.rid();
            byte[] kek = material.kek();
            try {
                assertArrayEquals(
                        HEX.parseHex("118a2b8aa53ceaf8d8341343368ae3db"),
                        rid
                );
                assertArrayEquals(
                        HEX.parseHex(
                                "42299fcde7930ae6fc402785a0c231f3"
                                        + "7886973394e7123f3e5bf58f3406209c"
                        ),
                        kek
                );
            } finally {
                clear(rid);
                clear(kek);
            }
        } finally {
            assertTrue(allZero(ssEcc));
            assertTrue(allZero(encapsulation.sharedSecret()));
            clear(ssPqInput);
            encapsulation.close();
        }
    }

    @Test
    void receiverContextDerivesX25519OnceAndDecapsulatesEveryEntry() {
        byte[] ssEcc = filled(32, (byte) 0x11);
        byte[] firstSsPq = filled(32, (byte) 0x21);
        byte[] secondSsPq = filled(32, (byte) 0x22);
        byte[] firstRidOutput = filled(16, (byte) 0x31);
        byte[] firstKekOutput = filled(32, (byte) 0x32);
        byte[] secondRidOutput = filled(16, (byte) 0x41);
        byte[] secondKekOutput = filled(32, (byte) 0x42);
        FixedX25519Crypto x25519 = new FixedX25519Crypto(ssEcc);
        FixedMlKem768Crypto mlkem768 = FixedMlKem768Crypto.forReceiver(
                firstSsPq,
                secondSsPq
        );
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(
                firstRidOutput,
                firstKekOutput,
                secondRidOutput,
                secondKekOutput
        );
        TrackingX25519Handle xHandle = new TrackingX25519Handle();
        TrackingMlKem768Handle pqHandle = new TrackingMlKem768Handle();
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                x25519,
                mlkem768,
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(xHandle, pqHandle, filled(32, (byte) 0x51));
             ObfuscationHybridKeyDeriver.DerivedMaterial first =
                     context.deriveEntry(filled(1088, (byte) 0x61));
             ObfuscationHybridKeyDeriver.DerivedMaterial second =
                     context.deriveEntry(filled(1088, (byte) 0x62))) {
            assertEquals(1, x25519.calls);
            assertEquals(2, mlkem768.decapsulationCalls);
            assertEquals(4, hkdf.calls.size());
            assertFalse(context.candidateCryptoFailed());
            assertFalse(first.candidateCryptoFailed());
            assertFalse(second.candidateCryptoFailed());

            assertArrayEquals(
                    concatenate(filled(32, (byte) 0x11), filled(32, (byte) 0x21)),
                    hkdf.calls.get(0).ikmSnapshot()
            );
            assertArrayEquals(
                    concatenate(filled(32, (byte) 0x11), filled(32, (byte) 0x21)),
                    hkdf.calls.get(1).ikmSnapshot()
            );
            assertArrayEquals(
                    concatenate(filled(32, (byte) 0x11), filled(32, (byte) 0x22)),
                    hkdf.calls.get(2).ikmSnapshot()
            );
            assertArrayEquals(
                    concatenate(filled(32, (byte) 0x11), filled(32, (byte) 0x22)),
                    hkdf.calls.get(3).ikmSnapshot()
            );
        }

        assertEquals(0, xHandle.closeCalls);
        assertEquals(0, pqHandle.closeCalls);
        assertTrue(allZero(ssEcc));
        assertTrue(allZero(firstSsPq));
        assertTrue(allZero(secondSsPq));
        assertTrue(allZero(firstRidOutput));
        assertTrue(allZero(firstKekOutput));
        assertTrue(allZero(secondRidOutput));
        assertTrue(allZero(secondKekOutput));
        assertTrue(hkdf.calls.stream().allMatch(call -> allZero(call.ikmArgument())));
    }

    @Test
    void senderPropagatesX25519AndEncapsulationCryptoFailuresWithoutDummyMaterial() {
        CryptoOperationException xFailure = new CryptoOperationException("x failed");
        FixedMlKem768Crypto unusedMlKem = new FixedMlKem768Crypto(
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 0x11))
        );
        RecordingHkdfCrypto unusedHkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x12),
                filled(32, (byte) 0x13)
        );
        ObfuscationHybridKeyDeriver xFailing = new ObfuscationHybridKeyDeriver(
                new ThrowingX25519Crypto(xFailure),
                unusedMlKem,
                unusedHkdf
        );

        assertSame(xFailure, assertThrows(
                CryptoOperationException.class,
                () -> xFailing.deriveForSender(
                        new TrackingX25519Handle(),
                        new byte[32],
                        new byte[1184]
                )
        ));
        assertEquals(0, unusedMlKem.encapsulationCalls);
        assertEquals(0, unusedHkdf.calls.size());

        CryptoOperationException encapsulationFailure =
                new CryptoOperationException("encapsulation failed");
        byte[] ssEcc = filled(32, (byte) 0x21);
        ThrowingMlKem768Crypto failingMlKem =
                ThrowingMlKem768Crypto.forEncapsulation(encapsulationFailure);
        RecordingHkdfCrypto secondUnusedHkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x22),
                filled(32, (byte) 0x23)
        );
        ObfuscationHybridKeyDeriver mlFailing = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                failingMlKem,
                secondUnusedHkdf
        );

        assertSame(encapsulationFailure, assertThrows(
                CryptoOperationException.class,
                () -> mlFailing.deriveForSender(
                        new TrackingX25519Handle(),
                        new byte[32],
                        new byte[1184]
                )
        ));
        assertEquals(1, failingMlKem.encapsulationCalls);
        assertEquals(0, secondUnusedHkdf.calls.size());
        assertTrue(allZero(ssEcc));
        unusedMlKem.encapsulation.close();
    }

    @Test
    void receiverLatchesX25519CryptoFailureAndStillDecapsulatesAndDerives() {
        CryptoOperationException xFailure = new CryptoOperationException("bad epk");
        byte[] ssPq = filled(32, (byte) 0x31);
        byte[] ridOutput = filled(16, (byte) 0x32);
        byte[] kekOutput = filled(32, (byte) 0x33);
        FixedMlKem768Crypto mlkem768 = FixedMlKem768Crypto.forReceiver(ssPq);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(ridOutput, kekOutput);
        TrackingX25519Handle xHandle = new TrackingX25519Handle();
        TrackingMlKem768Handle pqHandle = new TrackingMlKem768Handle();
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new ThrowingX25519Crypto(xFailure),
                mlkem768,
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(xHandle, pqHandle, new byte[32]);
             ObfuscationHybridKeyDeriver.DerivedMaterial material =
                     context.deriveEntry(new byte[1088])) {
            assertTrue(context.candidateCryptoFailed());
            assertTrue(material.candidateCryptoFailed());
            assertArrayEquals(filled(16, (byte) 0x32), material.rid());
            assertEquals(1, mlkem768.decapsulationCalls);
            assertEquals(2, hkdf.calls.size());
            assertArrayEquals(
                    concatenate(new byte[32], filled(32, (byte) 0x31)),
                    hkdf.calls.get(0).ikmSnapshot()
            );
            assertArrayEquals(
                    hkdf.calls.get(0).ikmSnapshot(),
                    hkdf.calls.get(1).ikmSnapshot()
            );
        }

        assertEquals(0, xHandle.closeCalls);
        assertEquals(0, pqHandle.closeCalls);
        assertTrue(allZero(ssPq));
        assertTrue(allZero(ridOutput));
        assertTrue(allZero(kekOutput));
    }

    @Test
    void receiverLatchesDecapsulationCryptoFailureAndDerivesWithDummyPqSecret() {
        byte[] ssEcc = filled(32, (byte) 0x41);
        CryptoOperationException decapsulationFailure =
                new CryptoOperationException("bad ek");
        byte[] ridOutput = filled(16, (byte) 0x42);
        byte[] kekOutput = filled(32, (byte) 0x43);
        ThrowingMlKem768Crypto mlkem768 =
                ThrowingMlKem768Crypto.forDecapsulation(decapsulationFailure);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(ridOutput, kekOutput);
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                mlkem768,
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             filled(32, (byte) 0x44)
                     );
             ObfuscationHybridKeyDeriver.DerivedMaterial material =
                     context.deriveEntry(filled(1088, (byte) 0x45))) {
            assertFalse(context.candidateCryptoFailed());
            assertTrue(material.candidateCryptoFailed());
            assertEquals(1, mlkem768.decapsulationCalls);
            assertEquals(2, hkdf.calls.size());
            assertArrayEquals(
                    concatenate(filled(32, (byte) 0x41), new byte[32]),
                    hkdf.calls.get(0).ikmSnapshot()
            );
        }

        assertTrue(allZero(ssEcc));
        assertTrue(allZero(ridOutput));
        assertTrue(allZero(kekOutput));
    }

    @Test
    void receiverTreatsAllZeroX25519AsCandidateFailureButAllowsAllZeroPqSecret() {
        byte[] zeroX = new byte[32];
        byte[] zeroPq = new byte[32];
        FixedMlKem768Crypto mlkem768 = FixedMlKem768Crypto.forReceiver(zeroPq);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x51),
                filled(32, (byte) 0x52)
        );
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(zeroX),
                mlkem768,
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     );
             ObfuscationHybridKeyDeriver.DerivedMaterial material =
                     context.deriveEntry(new byte[1088])) {
            assertTrue(context.candidateCryptoFailed());
            assertTrue(material.candidateCryptoFailed());
            assertEquals(1, mlkem768.decapsulationCalls);
            assertEquals(2, hkdf.calls.size());
        }
    }

    @Test
    void receiverDoesNotTreatAnAllZeroPqProviderOutputAsACandidateFailure() {
        byte[] ssEcc = filled(32, (byte) 0x5a);
        byte[] zeroPq = new byte[32];
        FixedMlKem768Crypto mlkem768 = FixedMlKem768Crypto.forReceiver(zeroPq);
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x5b),
                filled(32, (byte) 0x5c)
        );
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                mlkem768,
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     );
             ObfuscationHybridKeyDeriver.DerivedMaterial material =
                     context.deriveEntry(new byte[1088])) {
            assertFalse(context.candidateCryptoFailed());
            assertFalse(material.candidateCryptoFailed());
            assertEquals(1, mlkem768.decapsulationCalls);
        }
    }

    @Test
    void validatesDependenciesAndLengthsBeforeTheAffectedPrimitive() {
        FixedX25519Crypto x25519 = new FixedX25519Crypto(filled(32, (byte) 0x11));
        FixedMlKem768Crypto mlkem768 = new FixedMlKem768Crypto(
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 0x12))
        );
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x13),
                filled(32, (byte) 0x14)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new ObfuscationHybridKeyDeriver(null, mlkem768, hkdf)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ObfuscationHybridKeyDeriver(x25519, null, hkdf)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ObfuscationHybridKeyDeriver(x25519, mlkem768, null)
        );

        ObfuscationHybridKeyDeriver deriver =
                new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);
        TrackingX25519Handle xHandle = new TrackingX25519Handle();
        TrackingMlKem768Handle pqHandle = new TrackingMlKem768Handle();

        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.deriveForSender(null, new byte[32], new byte[1184])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.deriveForSender(xHandle, new byte[31], new byte[1184])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.deriveForSender(xHandle, new byte[32], new byte[1183])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.openForReceiver(null, pqHandle, new byte[32])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.openForReceiver(xHandle, null, new byte[32])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> deriver.openForReceiver(xHandle, pqHandle, new byte[33])
        );
        assertEquals(0, x25519.calls);
        assertEquals(0, mlkem768.encapsulationCalls + mlkem768.decapsulationCalls);
        assertEquals(0, hkdf.calls.size());

        byte[] secondXSecret = filled(32, (byte) 0x21);
        FixedMlKem768Crypto receiverMlKem = FixedMlKem768Crypto.forReceiver(
                filled(32, (byte) 0x22)
        );
        RecordingHkdfCrypto receiverHkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x23),
                filled(32, (byte) 0x24)
        );
        ObfuscationHybridKeyDeriver receiverDeriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(secondXSecret),
                receiverMlKem,
                receiverHkdf
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     receiverDeriver.openForReceiver(xHandle, pqHandle, new byte[32])) {
            assertThrows(IllegalArgumentException.class, () -> context.deriveEntry(null));
            assertThrows(IllegalArgumentException.class, () -> context.deriveEntry(new byte[1087]));
            assertThrows(IllegalArgumentException.class, () -> context.deriveEntry(new byte[1089]));
            assertEquals(0, receiverMlKem.decapsulationCalls);
            assertEquals(0, receiverHkdf.calls.size());
        }

        mlkem768.encapsulation.close();
    }

    @Test
    void providerContractAndLocalHandleFailuresAreNotCandidateFailures() {
        NullMlKem768Crypto nullMlKem = new NullMlKem768Crypto();
        byte[] senderXSecret = filled(32, (byte) 0x31);
        ObfuscationHybridKeyDeriver nullEncapsulation = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(senderXSecret),
                nullMlKem,
                new BouncyCastleHkdfCrypto()
        );
        assertThrows(
                IllegalStateException.class,
                () -> nullEncapsulation.deriveForSender(
                        new TrackingX25519Handle(),
                        new byte[32],
                        new byte[1184]
                )
        );
        assertTrue(allZero(senderXSecret));

        ObfuscationHybridKeyDeriver nullXSecret = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(null),
                FixedMlKem768Crypto.forReceiver(filled(32, (byte) 0x32)),
                new BouncyCastleHkdfCrypto()
        );
        assertThrows(
                IllegalStateException.class,
                () -> nullXSecret.openForReceiver(
                        new TrackingX25519Handle(),
                        new TrackingMlKem768Handle(),
                        new byte[32]
                )
        );

        byte[] receiverXSecret = filled(32, (byte) 0x33);
        ObfuscationHybridKeyDeriver nullPqSecret = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(receiverXSecret),
                nullMlKem,
                new BouncyCastleHkdfCrypto()
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     nullPqSecret.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
            assertFalse(context.candidateCryptoFailed());
        }

        IllegalStateException closed = new IllegalStateException("closed");
        ObfuscationHybridKeyDeriver closedHandle = new ObfuscationHybridKeyDeriver(
                new ThrowingX25519Crypto(closed),
                nullMlKem,
                new BouncyCastleHkdfCrypto()
        );
        assertSame(closed, assertThrows(
                IllegalStateException.class,
                () -> closedHandle.openForReceiver(
                        new TrackingX25519Handle(),
                        new TrackingMlKem768Handle(),
                        new byte[32]
                )
        ));

        IllegalArgumentException foreign = new IllegalArgumentException("foreign");
        ObfuscationHybridKeyDeriver foreignHandle = new ObfuscationHybridKeyDeriver(
                new ThrowingX25519Crypto(foreign),
                nullMlKem,
                new BouncyCastleHkdfCrypto()
        );
        assertSame(foreign, assertThrows(
                IllegalArgumentException.class,
                () -> foreignHandle.openForReceiver(
                        new TrackingX25519Handle(),
                        new TrackingMlKem768Handle(),
                        new byte[32]
                )
        ));

        byte[] closedMlKemXSecret = filled(32, (byte) 0x34);
        ObfuscationHybridKeyDeriver closedMlKemHandle = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(closedMlKemXSecret),
                ThrowingMlKem768Crypto.forDecapsulation(closed),
                new BouncyCastleHkdfCrypto()
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     closedMlKemHandle.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertSame(closed, assertThrows(
                    IllegalStateException.class,
                    () -> context.deriveEntry(new byte[1088])
            ));
            assertFalse(context.candidateCryptoFailed());
        }
        assertTrue(allZero(closedMlKemXSecret));

        byte[] foreignMlKemXSecret = filled(32, (byte) 0x35);
        ObfuscationHybridKeyDeriver foreignMlKemHandle = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(foreignMlKemXSecret),
                ThrowingMlKem768Crypto.forDecapsulation(foreign),
                new BouncyCastleHkdfCrypto()
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     foreignMlKemHandle.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertSame(foreign, assertThrows(
                    IllegalArgumentException.class,
                    () -> context.deriveEntry(new byte[1088])
            ));
            assertFalse(context.candidateCryptoFailed());
        }
        assertTrue(allZero(foreignMlKemXSecret));
    }

    @Test
    void rejectsAndClearsWrongLengthPrimitiveAndHkdfOutputs() {
        byte[] malformedX = filled(31, (byte) 0x61);
        ObfuscationHybridKeyDeriver badX = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(malformedX),
                new NullMlKem768Crypto(),
                new BouncyCastleHkdfCrypto()
        );
        assertThrows(
                IllegalStateException.class,
                () -> badX.openForReceiver(
                        new TrackingX25519Handle(),
                        new TrackingMlKem768Handle(),
                        new byte[32]
                )
        );
        assertTrue(allZero(malformedX));

        byte[] ssEcc = filled(32, (byte) 0x62);
        byte[] malformedPq = filled(31, (byte) 0x63);
        ObfuscationHybridKeyDeriver badPq = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                FixedMlKem768Crypto.forReceiver(malformedPq),
                new BouncyCastleHkdfCrypto()
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     badPq.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
            assertFalse(context.candidateCryptoFailed());
        }
        assertTrue(allZero(malformedPq));

        byte[] firstX = filled(32, (byte) 0x64);
        byte[] firstPq = filled(32, (byte) 0x65);
        byte[] malformedRid = filled(15, (byte) 0x66);
        ObfuscationHybridKeyDeriver badRid = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(firstX),
                FixedMlKem768Crypto.forReceiver(firstPq),
                new RecordingHkdfCrypto(malformedRid)
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     badRid.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
        }
        assertTrue(allZero(malformedRid));

        byte[] secondX = filled(32, (byte) 0x67);
        byte[] secondPq = filled(32, (byte) 0x68);
        byte[] ridOutput = filled(16, (byte) 0x69);
        byte[] malformedKek = filled(31, (byte) 0x6a);
        ObfuscationHybridKeyDeriver badKek = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(secondX),
                FixedMlKem768Crypto.forReceiver(secondPq),
                new RecordingHkdfCrypto(ridOutput, malformedKek)
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     badKek.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
        }
        assertTrue(allZero(ridOutput));
        assertTrue(allZero(malformedKek));

        byte[] thirdX = filled(32, (byte) 0x6b);
        byte[] thirdPq = filled(32, (byte) 0x6c);
        ObfuscationHybridKeyDeriver nullRid = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(thirdX),
                FixedMlKem768Crypto.forReceiver(thirdPq),
                new NullHkdfCrypto()
        );
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     nullRid.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
        }
    }

    @Test
    void senderRejectsAllZeroX25519WithoutEncapsulating() {
        byte[] zeroX = new byte[32];
        FixedMlKem768Crypto mlkem768 = new FixedMlKem768Crypto(
                new MLKem768Encapsulation(new byte[1088], filled(32, (byte) 0x71))
        );
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(zeroX),
                mlkem768,
                new BouncyCastleHkdfCrypto()
        );

        assertThrows(
                CryptoOperationException.class,
                () -> deriver.deriveForSender(
                        new TrackingX25519Handle(),
                        new byte[32],
                        new byte[1184]
                )
        );
        assertEquals(0, mlkem768.encapsulationCalls);
        mlkem768.encapsulation.close();
    }

    @Test
    void hkdfFailureIsAProviderContractFailureAndClearsCombinedInputs() {
        byte[] ssEcc = filled(32, (byte) 0x41);
        byte[] ssPq = filled(32, (byte) 0x42);
        CryptoOperationException hkdfFailure = new CryptoOperationException("hkdf failed");
        ThrowingHkdfCrypto hkdf = new ThrowingHkdfCrypto(hkdfFailure);
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                FixedMlKem768Crypto.forReceiver(ssPq),
                hkdf
        );

        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     deriver.openForReceiver(
                             new TrackingX25519Handle(),
                             new TrackingMlKem768Handle(),
                             new byte[32]
                     )) {
            IllegalStateException wrapper = assertThrows(
                    IllegalStateException.class,
                    () -> context.deriveEntry(new byte[1088])
            );
            assertSame(hkdfFailure, wrapper.getCause());
            assertFalse(context.candidateCryptoFailed());
        }

        assertEquals(1, hkdf.ikmArguments.size());
        assertTrue(allZero(hkdf.ikmArguments.get(0)));
        assertTrue(allZero(ssEcc));
        assertTrue(allZero(ssPq));
    }

    @Test
    void eachSenderDerivationPerformsAnIndependentEncapsulation() {
        QueueX25519Crypto x25519 = new QueueX25519Crypto(
                filled(32, (byte) 0x51),
                filled(32, (byte) 0x52)
        );
        MLKem768Encapsulation firstEncapsulation = new MLKem768Encapsulation(
                filled(1088, (byte) 0x61),
                filled(32, (byte) 0x62)
        );
        MLKem768Encapsulation secondEncapsulation = new MLKem768Encapsulation(
                filled(1088, (byte) 0x71),
                filled(32, (byte) 0x72)
        );
        QueueMlKem768Crypto mlkem768 = new QueueMlKem768Crypto(
                firstEncapsulation,
                secondEncapsulation
        );
        RecordingHkdfCrypto hkdf = new RecordingHkdfCrypto(
                filled(16, (byte) 0x01),
                filled(32, (byte) 0x02),
                filled(16, (byte) 0x03),
                filled(32, (byte) 0x04)
        );
        ObfuscationHybridKeyDeriver deriver =
                new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);
        TrackingX25519Handle handle = new TrackingX25519Handle();

        try (ObfuscationHybridKeyDeriver.SenderMaterial first =
                     deriver.deriveForSender(handle, new byte[32], new byte[1184]);
             ObfuscationHybridKeyDeriver.SenderMaterial second =
                     deriver.deriveForSender(handle, new byte[32], new byte[1184])) {
            byte[] firstEk = first.ek();
            byte[] secondEk = second.ek();
            try {
                assertFalse(Arrays.equals(firstEk, secondEk));
                assertArrayEquals(filled(1088, (byte) 0x61), firstEk);
                assertArrayEquals(filled(1088, (byte) 0x71), secondEk);
            } finally {
                clear(firstEk);
                clear(secondEk);
            }
        }

        assertEquals(2, x25519.calls);
        assertEquals(2, mlkem768.encapsulationCalls);
        assertEquals(0, handle.closeCalls);
    }

    @Test
    void materialAndContextOwnCopiesClearSecretsAndNeverCloseBorrowedHandles() throws Exception {
        byte[] ssEcc = filled(32, (byte) 0x11);
        byte[] ssPq = filled(32, (byte) 0x12);
        byte[] ridOutput = filled(16, (byte) 0x13);
        byte[] kekOutput = filled(32, (byte) 0x14);
        TrackingX25519Handle xHandle = new TrackingX25519Handle();
        TrackingMlKem768Handle pqHandle = new TrackingMlKem768Handle();
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                FixedMlKem768Crypto.forReceiver(ssPq),
                new RecordingHkdfCrypto(ridOutput, kekOutput)
        );

        ObfuscationHybridKeyDeriver.ReceiverContext context =
                deriver.openForReceiver(xHandle, pqHandle, new byte[32]);
        ObfuscationHybridKeyDeriver.DerivedMaterial material =
                context.deriveEntry(new byte[1088]);
        byte[] firstRid = material.rid();
        byte[] secondRid = material.rid();
        byte[] firstKek = material.kek();
        byte[] secondKek = material.kek();
        try {
            assertNotSame(firstRid, secondRid);
            assertNotSame(firstKek, secondKek);
            firstRid[0] ^= 1;
            firstKek[0] ^= 1;
            assertArrayEquals(filled(16, (byte) 0x13), secondRid);
            assertArrayEquals(filled(32, (byte) 0x14), secondKek);
        } finally {
            clear(firstRid);
            clear(secondRid);
            clear(firstKek);
            clear(secondKek);
        }

        byte[] contextSecret = bytesField(context, "ssEcc");
        byte[] materialRid = bytesField(material, "rid");
        byte[] materialKek = bytesField(material, "kek");
        material.close();
        assertDoesNotThrow(material::close);
        context.close();
        assertDoesNotThrow(context::close);
        assertTrue(allZero(contextSecret));
        assertTrue(allZero(materialRid));
        assertTrue(allZero(materialKek));
        assertThrows(IllegalStateException.class, material::rid);
        assertThrows(IllegalStateException.class, material::kek);
        assertThrows(IllegalStateException.class, material::candidateCryptoFailed);
        assertThrows(IllegalStateException.class, context::candidateCryptoFailed);
        assertThrows(IllegalStateException.class, () -> context.deriveEntry(new byte[1088]));
        assertEquals(0, xHandle.closeCalls);
        assertEquals(0, pqHandle.closeCalls);
    }

    @Test
    void senderMaterialOwnsCopiesClearsSecretsAndKeepsPublicEk() throws Exception {
        byte[] ssEcc = filled(32, (byte) 0x21);
        byte[] ssPq = filled(32, (byte) 0x22);
        byte[] ridOutput = filled(16, (byte) 0x23);
        byte[] kekOutput = filled(32, (byte) 0x24);
        byte[] ekInput = filled(1088, (byte) 0x25);
        byte[] expectedEk = ekInput.clone();
        TrackingX25519Handle handle = new TrackingX25519Handle();
        ObfuscationHybridKeyDeriver deriver = new ObfuscationHybridKeyDeriver(
                new FixedX25519Crypto(ssEcc),
                new FixedMlKem768Crypto(new MLKem768Encapsulation(ekInput, ssPq)),
                new RecordingHkdfCrypto(ridOutput, kekOutput)
        );

        ObfuscationHybridKeyDeriver.SenderMaterial material = deriver.deriveForSender(
                handle,
                new byte[32],
                new byte[1184]
        );
        byte[] firstRid = material.rid();
        byte[] secondRid = material.rid();
        byte[] firstKek = material.kek();
        byte[] secondKek = material.kek();
        byte[] firstEk = material.ek();
        byte[] secondEk = material.ek();
        try {
            assertNotSame(firstRid, secondRid);
            assertNotSame(firstKek, secondKek);
            assertNotSame(firstEk, secondEk);
            firstRid[0] ^= 1;
            firstKek[0] ^= 1;
            firstEk[0] ^= 1;
            assertArrayEquals(filled(16, (byte) 0x23), secondRid);
            assertArrayEquals(filled(32, (byte) 0x24), secondKek);
            assertArrayEquals(expectedEk, secondEk);
        } finally {
            clear(firstRid);
            clear(secondRid);
            clear(firstKek);
            clear(secondKek);
            clear(firstEk);
            clear(secondEk);
        }

        byte[] internalRid = bytesField(material, "rid");
        byte[] internalKek = bytesField(material, "kek");
        byte[] internalEk = bytesField(material, "ek");
        material.close();
        assertDoesNotThrow(material::close);
        assertTrue(allZero(internalRid));
        assertTrue(allZero(internalKek));
        assertArrayEquals(expectedEk, internalEk);
        assertThrows(IllegalStateException.class, material::rid);
        assertThrows(IllegalStateException.class, material::kek);
        assertThrows(IllegalStateException.class, material::ek);
        assertEquals(0, handle.closeCalls);
        clear(expectedEk);
        clear(ekInput);
    }

    private static byte[] bytesField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(target);
    }

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

    private static byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
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

    private static final class TrackingX25519Handle implements X25519PrivateKeyHandle {
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

    private static final class TrackingMlKem768Handle implements MLKem768PrivateKeyHandle {
        private int closeCalls;

        @Override
        public byte[] publicKey() {
            return new byte[1184];
        }

        @Override
        public void close() {
            closeCalls++;
        }
    }

    private static final class FixedX25519Crypto implements X25519Crypto {
        private final byte[] sharedSecret;
        private int calls;

        private FixedX25519Crypto(byte[] sharedSecret) {
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
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey,
                byte[] peerPublicKey
        ) {
            calls++;
            return sharedSecret;
        }
    }

    private static final class FixedMlKem768Crypto implements MLKem768Crypto {
        private final MLKem768Encapsulation encapsulation;
        private final Deque<byte[]> decapsulationResults;
        private int decapsulationCalls;
        private int encapsulationCalls;

        private FixedMlKem768Crypto(MLKem768Encapsulation encapsulation) {
            this.encapsulation = encapsulation;
            this.decapsulationResults = new ArrayDeque<>();
        }

        private FixedMlKem768Crypto(Deque<byte[]> decapsulationResults) {
            this.encapsulation = null;
            this.decapsulationResults = decapsulationResults;
        }

        private static FixedMlKem768Crypto forReceiver(byte[]... results) {
            return new FixedMlKem768Crypto(new ArrayDeque<>(List.of(results)));
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
            return encapsulation;
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            decapsulationCalls++;
            return decapsulationResults.removeFirst();
        }
    }

    private static final class ThrowingX25519Crypto implements X25519Crypto {
        private final RuntimeException failure;

        private ThrowingX25519Crypto(RuntimeException failure) {
            this.failure = failure;
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
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey,
                byte[] peerPublicKey
        ) {
            throw failure;
        }
    }

    private static final class QueueX25519Crypto implements X25519Crypto {
        private final Deque<byte[]> secrets;
        private int calls;

        private QueueX25519Crypto(byte[]... secrets) {
            this.secrets = new ArrayDeque<>(List.of(secrets));
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
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey,
                byte[] peerPublicKey
        ) {
            calls++;
            return secrets.removeFirst();
        }
    }

    private static final class ThrowingMlKem768Crypto implements MLKem768Crypto {
        private final RuntimeException encapsulationFailure;
        private final RuntimeException decapsulationFailure;
        private int encapsulationCalls;
        private int decapsulationCalls;

        private ThrowingMlKem768Crypto(
                RuntimeException encapsulationFailure,
                RuntimeException decapsulationFailure
        ) {
            this.encapsulationFailure = encapsulationFailure;
            this.decapsulationFailure = decapsulationFailure;
        }

        private static ThrowingMlKem768Crypto forEncapsulation(RuntimeException failure) {
            return new ThrowingMlKem768Crypto(failure, null);
        }

        private static ThrowingMlKem768Crypto forDecapsulation(RuntimeException failure) {
            return new ThrowingMlKem768Crypto(null, failure);
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
            throw encapsulationFailure;
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            decapsulationCalls++;
            throw decapsulationFailure;
        }
    }

    private static final class QueueMlKem768Crypto implements MLKem768Crypto {
        private final Deque<MLKem768Encapsulation> encapsulations;
        private int encapsulationCalls;

        private QueueMlKem768Crypto(MLKem768Encapsulation... encapsulations) {
            this.encapsulations = new ArrayDeque<>(List.of(encapsulations));
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
            return encapsulations.removeFirst();
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class NullMlKem768Crypto implements MLKem768Crypto {
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
            return null;
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey,
                byte[] ciphertext
        ) {
            return null;
        }
    }

    private static final class MutatingHkdfCrypto implements HkdfCrypto {
        private final List<byte[]> ikmSnapshots = new ArrayList<>();
        private final List<byte[]> ikmArguments = new ArrayList<>();

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
            ikmSnapshots.add(ikm.clone());
            ikmArguments.add(ikm);
            Arrays.fill(ikm, (byte) 0);
            return filled(length, (byte) length);
        }
    }

    private static final class RecordingHkdfCrypto implements HkdfCrypto {
        private final Deque<byte[]> outputs;
        private final List<HkdfCall> calls = new ArrayList<>();

        private RecordingHkdfCrypto(byte[]... outputs) {
            this.outputs = new ArrayDeque<>(List.of(outputs));
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
            calls.add(new HkdfCall(ikm, ikm.clone()));
            return outputs.removeFirst();
        }
    }

    private static final class ThrowingHkdfCrypto implements HkdfCrypto {
        private final RuntimeException failure;
        private final List<byte[]> ikmArguments = new ArrayList<>();

        private ThrowingHkdfCrypto(RuntimeException failure) {
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
            ikmArguments.add(ikm);
            throw failure;
        }
    }

    private static final class NullHkdfCrypto implements HkdfCrypto {
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
            return null;
        }
    }

    private record HkdfCall(byte[] ikmArgument, byte[] ikmSnapshot) {
    }
}
