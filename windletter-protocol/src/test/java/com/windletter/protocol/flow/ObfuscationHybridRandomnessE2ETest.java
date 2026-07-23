package com.windletter.protocol.flow;

import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ObfuscationHybridRandomnessE2ETest {

    @Test
    void identicalInputUsesFreshEpkIvTargetRidTargetEkAndCiphertext() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            WindLetter first = new JacksonOuterWireParser().parse(
                    fixture.send(fixture.binaryPayload())
            );
            WindLetter second = new JacksonOuterWireParser().parse(
                    fixture.send(fixture.binaryPayload())
            );

            byte[] firstEpk = ((Epk) first.protectedHeader().senderInfo()).x();
            byte[] secondEpk = ((Epk) second.protectedHeader().senderInfo()).x();
            byte[] firstIv = first.iv();
            byte[] secondIv = second.iv();
            byte[] firstCiphertext = first.ciphertext();
            byte[] secondCiphertext = second.ciphertext();
            try (Match firstMatch = findMatch(fixture, first, fixture.middle);
                 Match secondMatch = findMatch(fixture, second, fixture.middle)) {
                assertFalse(Arrays.equals(firstEpk, secondEpk));
                assertFalse(Arrays.equals(firstIv, secondIv));
                assertFalse(firstMatch.hasSameRid(secondMatch));
                assertFalse(firstMatch.hasSameEk(secondMatch));
                assertFalse(Arrays.equals(firstCiphertext, secondCiphertext));
            } finally {
                clear(firstEpk);
                clear(secondEpk);
                clear(firstIv);
                clear(secondIv);
                clear(firstCiphertext);
                clear(secondCiphertext);
            }
        }
    }

    private static Match findMatch(
            ObfuscationHybridFlowTestFixtures fixture,
            WindLetter letter,
            ObfuscationHybridFlowTestFixtures.HybridPair pair
    ) {
        byte[] epkX = ((Epk) letter.protectedHeader().senderInfo()).x();
        byte[] selectedRid = null;
        byte[] selectedEk = null;
        int matches = 0;
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     fixture.keyDeriver.openForReceiver(
                             pair.x25519, pair.mlkem768, epkX
                     )) {
            try {
                for (int index = 0; index < letter.recipients().size(); index++) {
                    ObfuscationRecipient recipient =
                            (ObfuscationRecipient) letter.recipients().get(index);
                    byte[] ek = recipient.ek();
                    byte[] wireRid = recipient.rid();
                    try (ObfuscationHybridKeyDeriver.DerivedMaterial material =
                                 context.deriveEntry(ek)) {
                        byte[] derivedRid = material.rid();
                        try {
                            if (!material.candidateCryptoFailed()
                                    && MessageDigest.isEqual(derivedRid, wireRid)) {
                                matches++;
                                clear(selectedRid);
                                clear(selectedEk);
                                selectedRid = wireRid.clone();
                                selectedEk = ek.clone();
                            }
                        } finally {
                            clear(derivedRid);
                        }
                    } finally {
                        clear(ek);
                        clear(wireRid);
                    }
                }
                assertEquals(1, matches);
                return new Match(selectedRid, selectedEk);
            } finally {
                clear(selectedRid);
                clear(selectedEk);
            }
        } finally {
            clear(epkX);
        }
    }

    private static void clear(byte[] value) {
        ObfuscationHybridFlowTestFixtures.clear(value);
    }

    private record Match(byte[] rid, byte[] ek) implements AutoCloseable {
        private Match {
            rid = rid.clone();
            ek = ek.clone();
        }

        boolean hasSameRid(Match other) {
            return Arrays.equals(rid, other.rid);
        }

        boolean hasSameEk(Match other) {
            return Arrays.equals(ek, other.ek);
        }

        @Override
        public void close() {
            clear(rid);
            clear(ek);
        }
    }
}
