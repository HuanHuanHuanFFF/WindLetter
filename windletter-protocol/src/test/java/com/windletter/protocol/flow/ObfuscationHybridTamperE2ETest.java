package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridTamperE2ETest {

    @Test
    void staleAadRejectsEveryHybridRecipientFieldBeforeLocalPairValidation() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String original = fixture.send(fixture.binaryPayload());
            List<ObfuscationHybridRecipientPrivateKeys> poisoned =
                    Arrays.asList((ObfuscationHybridRecipientPrivateKeys) null);

            for (String field : List.of("rid", "ek", "encrypted_key")) {
                ObjectNode root = parseObject(original);
                flipEncodedField(
                        (ObjectNode) root.withArray("recipients").get(0), field
                );
                assertUnsignedFailure(ErrorCode.AAD_MISMATCH, () ->
                        fixture.receiver().receive(fixture.request(
                                write(root), poisoned
                        ))
                );
            }
        }
    }

    @Test
    void swappedExactLengthEkCompletesRecoveryAsNotForMe() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String original = fixture.send(fixture.binaryPayload());
            try (Match target = findMatch(fixture, original, fixture.middle)) {
                ObjectNode root = parseObject(original);
                ArrayNode recipients = root.withArray("recipients");
                int otherIndex = (target.wireIndex() + 1) % recipients.size();
                ObjectNode targetEntry = (ObjectNode) recipients.get(target.wireIndex());
                ObjectNode otherEntry = (ObjectNode) recipients.get(otherIndex);
                String targetEk = targetEntry.get("ek").textValue();
                targetEntry.put("ek", otherEntry.get("ek").textValue());
                otherEntry.put("ek", targetEk);
                recomputeAad(root);

                assertUnsignedFailure(ErrorCode.NOT_FOR_ME, () ->
                        fixture.receiver().receive(fixture.request(
                                write(root), List.of(fixture.middle.privateKeys())
                        ))
                );
            }
        }
    }

    @Test
    void selectedWrappedKeyFailureIsGenericAndNeverFallsBack() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String original = fixture.send(fixture.binaryPayload());
            try (Match first = findMatch(fixture, original, fixture.first);
                 Match last = findMatch(fixture, original, fixture.last)) {
                Match selected = first.wireIndex() < last.wireIndex() ? first : last;
                Match fallback = selected == first ? last : first;
                ObfuscationHybridFlowTestFixtures.HybridPair selectedPair =
                        selected == first ? fixture.first : fixture.last;
                ObfuscationHybridFlowTestFixtures.HybridPair fallbackPair =
                        selected == first ? fixture.last : fixture.first;

                ObjectNode root = parseObject(original);
                flipEncodedField(
                        (ObjectNode) root.withArray("recipients")
                                .get(selected.wireIndex()),
                        "encrypted_key"
                );
                recomputeAad(root);

                ProtocolException failure = assertUnsignedFailure(
                        ErrorCode.KEY_UNWRAP_FAILED,
                        () -> fixture.receiver().receive(fixture.request(
                                write(root),
                                List.of(fallbackPair.privateKeys(),
                                        selectedPair.privateKeys())
                        ))
                );
                assertGenericRecovery(failure);
                assertNotEquals(selected.wireIndex(), fallback.wireIndex());
            }
        }
    }

    @Test
    void changedOrderIvCiphertextAndTagFailOuterAuthentication() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String original = fixture.send(fixture.binaryPayload());

            ObjectNode reordered = parseObject(original);
            ArrayNode recipients = reordered.withArray("recipients");
            JsonNode first = recipients.get(0).deepCopy();
            recipients.set(0, recipients.get(1).deepCopy());
            recipients.set(1, first);
            recomputeAad(reordered);
            assertUnsignedFailure(ErrorCode.GCM_AUTH_FAILED, () ->
                    fixture.receiver().receive(fixture.request(
                            write(reordered), List.of(fixture.middle.privateKeys())
                    ))
            );

            for (String field : List.of("iv", "ciphertext", "tag")) {
                ObjectNode root = parseObject(original);
                flipEncodedField(root, field);
                assertUnsignedFailure(ErrorCode.GCM_AUTH_FAILED, () ->
                        fixture.receiver().receive(fixture.request(
                                write(root), List.of(fixture.middle.privateKeys())
                        ))
                );
            }
        }
    }

    @Test
    void legalRandomAndLowOrderEpkKeepTheirDistinctGenericOutcomes() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String original = fixture.send(fixture.binaryPayload());
            byte[] randomEpk = fixture.unrelated.x25519.publicKey();
            byte[] lowOrderEpk = new byte[32];
            try {
                assertUnsignedFailure(ErrorCode.NOT_FOR_ME, () ->
                        fixture.receiver().receive(fixture.request(
                                ObfuscationX25519FlowTestFixtures.replaceEpkX(
                                        original, randomEpk
                                ),
                                List.of(fixture.middle.privateKeys())
                        ))
                );
                ProtocolException failure = assertUnsignedFailure(
                        ErrorCode.KEY_UNWRAP_FAILED,
                        () -> fixture.receiver().receive(fixture.request(
                                ObfuscationX25519FlowTestFixtures.replaceEpkX(
                                        original, lowOrderEpk
                                ),
                                List.of(fixture.middle.privateKeys())
                        ))
                );
                assertGenericRecovery(failure);
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(randomEpk);
                ObfuscationHybridFlowTestFixtures.clear(lowOrderEpk);
            }
        }
    }

    @Test
    void authenticatedBindingAndSignatureFailuresReleaseNoPayloadOrIdentity() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String unsigned = fixture.send(fixture.binaryPayload());
            assertUnsignedFailure(ErrorCode.BINDING_FAILED, () ->
                    fixture.receiver().receive(fixture.request(
                            fixture.authenticatedWrongBinding(
                                    unsigned, fixture.middle
                            ),
                            List.of(fixture.middle.privateKeys())
                    ))
            );

            String signed = fixture.sendSigned(fixture.binaryPayload());
            AtomicInteger resolverCalls = new AtomicInteger();
            assertSignedFailure(ErrorCode.BINDING_FAILED, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedSignedWrongBinding(
                                    signed, fixture.middle
                            ),
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.middle.privateKeys())
                    ))
            );
            assertEquals(0, resolverCalls.get());

            assertSignedFailure(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedFlippedSignature(
                                    signed, fixture.middle
                            ),
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    ))
            );
            assertSignedFailure(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedUnknownSigner(
                                    signed, fixture.middle
                            ),
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    ))
            );
        }
    }

    private static Match findMatch(
            ObfuscationHybridFlowTestFixtures fixture,
            String wire,
            ObfuscationHybridFlowTestFixtures.HybridPair pair
    ) {
        WindLetter parsed = new com.windletter.protocol.parser.JacksonOuterWireParser()
                .parse(wire);
        byte[] epkX = ((Epk) parsed.protectedHeader().senderInfo()).x();
        try (ObfuscationHybridKeyDeriver.ReceiverContext context =
                     fixture.keyDeriver.openForReceiver(
                             pair.x25519, pair.mlkem768, epkX
                     )) {
            for (int index = 0; index < parsed.recipients().size(); index++) {
                ObfuscationRecipient recipient =
                        (ObfuscationRecipient) parsed.recipients().get(index);
                byte[] ek = recipient.ek();
                byte[] wireRid = recipient.rid();
                try (ObfuscationHybridKeyDeriver.DerivedMaterial material =
                             context.deriveEntry(ek)) {
                    byte[] derivedRid = material.rid();
                    try {
                        if (!material.candidateCryptoFailed()
                                && MessageDigest.isEqual(derivedRid, wireRid)) {
                            return new Match(index, wireRid, ek);
                        }
                    } finally {
                        ObfuscationHybridFlowTestFixtures.clear(derivedRid);
                    }
                } finally {
                    ObfuscationHybridFlowTestFixtures.clear(ek);
                    ObfuscationHybridFlowTestFixtures.clear(wireRid);
                }
            }
            throw new AssertionError("real Hybrid recipient entry not found");
        } finally {
            ObfuscationHybridFlowTestFixtures.clear(epkX);
        }
    }

    private static ProtocolException assertUnsignedFailure(
            ErrorCode expected,
            Supplier<ObfuscationHybridUnsignedReceiver.Result> operation
    ) {
        AtomicReference<ObfuscationHybridUnsignedReceiver.Result> released =
                new AtomicReference<>();
        ProtocolException failure = assertThrows(
                ProtocolException.class,
                () -> released.set(operation.get())
        );
        assertEquals(expected, failure.errorCode());
        assertNull(released.get());
        return failure;
    }

    private static ProtocolException assertSignedFailure(
            ErrorCode expected,
            Supplier<ObfuscationHybridSignedReceiver.Result> operation
    ) {
        AtomicReference<ObfuscationHybridSignedReceiver.Result> released =
                new AtomicReference<>();
        ProtocolException failure = assertThrows(
                ProtocolException.class,
                () -> released.set(operation.get())
        );
        assertEquals(expected, failure.errorCode());
        assertNull(released.get());
        return failure;
    }

    private static void assertGenericRecovery(ProtocolException failure) {
        assertEquals(ErrorCode.KEY_UNWRAP_FAILED, failure.errorCode());
        assertEquals(
                "obfuscation hybrid recipient key recovery failed",
                failure.getMessage()
        );
        assertNull(failure.getCause());
    }

    private record Match(int wireIndex, byte[] rid, byte[] ek)
            implements AutoCloseable {
        private Match {
            rid = rid.clone();
            ek = ek.clone();
        }

        @Override
        public void close() {
            ObfuscationHybridFlowTestFixtures.clear(rid);
            ObfuscationHybridFlowTestFixtures.clear(ek);
        }
    }
}
