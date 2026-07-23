package com.windletter.protocol.flow;

import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.clear;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ObfuscationX25519RandomnessE2ETest {

    @Test
    void identicalBusinessInputUsesFreshEpkIvTargetRidAndCiphertext() {
        try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                     new ObfuscationX25519FlowTestFixtures.Fixture()) {
            String firstWire = fixture.send(fixture.binaryPayload());
            String secondWire = fixture.send(fixture.binaryPayload());
            WindLetter first = new JacksonOuterWireParser().parse(firstWire);
            WindLetter second = new JacksonOuterWireParser().parse(secondWire);

            byte[] testOwnedFirstEpk = ((Epk) first.protectedHeader().senderInfo()).x();
            byte[] testOwnedSecondEpk = ((Epk) second.protectedHeader().senderInfo()).x();
            byte[] testOwnedFirstIv = first.iv();
            byte[] testOwnedSecondIv = second.iv();
            byte[] testOwnedFirstCiphertext = first.ciphertext();
            byte[] testOwnedSecondCiphertext = second.ciphertext();
            byte[] testOwnedFirstTargetRid = null;
            byte[] testOwnedSecondTargetRid = null;
            try {
                ObfuscationX25519KeyDeriver deriver =
                        new ObfuscationX25519KeyDeriver(
                                fixture.x25519, fixture.hkdf
                        );
                try (ObfuscationX25519KeyDeriver.DerivedMaterial firstMaterial =
                             deriver.derive(fixture.second, testOwnedFirstEpk);
                     ObfuscationX25519KeyDeriver.DerivedMaterial secondMaterial =
                             deriver.derive(fixture.second, testOwnedSecondEpk)) {
                    testOwnedFirstTargetRid = firstMaterial.rid();
                    testOwnedSecondTargetRid = secondMaterial.rid();

                    assertExactlyOnce(
                            testOwnedFirstTargetRid, first.recipients()
                    );
                    assertExactlyOnce(
                            testOwnedSecondTargetRid, second.recipients()
                    );
                    assertFalse(Arrays.equals(
                            testOwnedFirstEpk, testOwnedSecondEpk
                    ));
                    assertFalse(Arrays.equals(
                            testOwnedFirstIv, testOwnedSecondIv
                    ));
                    assertFalse(Arrays.equals(
                            testOwnedFirstTargetRid, testOwnedSecondTargetRid
                    ));
                    assertFalse(Arrays.equals(
                            testOwnedFirstCiphertext, testOwnedSecondCiphertext
                    ));
                }
            } finally {
                clear(testOwnedFirstEpk);
                clear(testOwnedSecondEpk);
                clear(testOwnedFirstIv);
                clear(testOwnedSecondIv);
                clear(testOwnedFirstCiphertext);
                clear(testOwnedSecondCiphertext);
                clear(testOwnedFirstTargetRid);
                clear(testOwnedSecondTargetRid);
            }
        }
    }

    private static void assertExactlyOnce(
            byte[] targetRid,
            List<RecipientEntry> recipients
    ) {
        int matches = 0;
        for (RecipientEntry entry : recipients) {
            byte[] testOwnedWireRid = ((ObfuscationRecipient) entry).rid();
            try {
                if (MessageDigest.isEqual(targetRid, testOwnedWireRid)) {
                    matches++;
                }
            } finally {
                clear(testOwnedWireRid);
            }
        }
        assertEquals(1, matches,
                "the target recipient rid must occur exactly once");
    }
}
