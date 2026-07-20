package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519TamperE2ETest {

    @Test
    void legalRandomEpkCompletesTheScanAsNotForMe() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.send(fixture.binaryPayload());
            byte[] testOwnedRandomEpk = fixture.unrelated.publicKey();
            try {
                String malicious = replaceEpkX(original, testOwnedRandomEpk);
                assertUnsignedFailure(ErrorCode.NOT_FOR_ME, () ->
                        fixture.receiver().receive(fixture.request(
                                malicious, List.of(fixture.second)
                        )));
            } finally {
                clear(testOwnedRandomEpk);
            }
        }
    }

    @Test
    void realBcLowOrderAndAllZeroEpkHaveOneGenericRecoveryFailure() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.send(fixture.binaryPayload());
            byte[] testOwnedAllZero = new byte[32];
            byte[] testOwnedLowOrderOne = new byte[32];
            testOwnedLowOrderOne[0] = 1;
            try {
                for (byte[] maliciousEpk : List.of(
                        testOwnedAllZero, testOwnedLowOrderOne
                )) {
                    ProtocolException failure = assertUnsignedFailure(
                            ErrorCode.KEY_UNWRAP_FAILED,
                            () -> fixture.receiver().receive(fixture.request(
                                    replaceEpkX(original, maliciousEpk),
                                    List.of(fixture.second)
                            ))
                    );
                    assertGenericKeyRecovery(failure);
                }
            } finally {
                clear(testOwnedAllZero);
                clear(testOwnedLowOrderOne);
            }
        }
    }

    @Test
    void staleAadRejectsRidReplacementAndDirectAadReplacementBeforeRouting() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.send(fixture.binaryPayload());
            List<X25519PrivateKeyHandle> poisoned = Arrays.asList(
                    (X25519PrivateKeyHandle) null
            );

            ObjectNode ridChanged = object(original);
            flipEncodedField(
                    (ObjectNode) ridChanged.withArray("recipients").get(0),
                    "rid"
            );
            assertUnsignedFailure(ErrorCode.AAD_MISMATCH, () ->
                    fixture.receiver().receive(fixture.request(
                            json(ridChanged), poisoned
                    )));

            ObjectNode aadChanged = object(original);
            flipEncodedField(aadChanged, "aad");
            assertUnsignedFailure(ErrorCode.AAD_MISMATCH, () ->
                    fixture.receiver().receive(fixture.request(
                            json(aadChanged), poisoned
                    )));
        }
    }

    @Test
    void duplicateRidWithRecomputedAadIsInvalidBeforeAnyLocalKeyRead() {
        try (Fixture fixture = new Fixture()) {
            ObjectNode root = object(fixture.send(fixture.binaryPayload()));
            ArrayNode recipients = root.withArray("recipients");
            ((ObjectNode) recipients.get(1)).put(
                    "rid", recipients.get(0).get("rid").textValue()
            );
            recomputeAad(root);

            List<X25519PrivateKeyHandle> poisoned = Arrays.asList(
                    (X25519PrivateKeyHandle) null
            );
            assertUnsignedFailure(ErrorCode.INVALID_FIELD, () ->
                    fixture.receiver().receive(fixture.request(
                            json(root), poisoned
                    )));
        }
    }

    @Test
    void selectedEncryptedKeyFailureIsGenericAndNeverFallsBack() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.send(fixture.binaryPayload());
            List<RealRecipientPosition> realRecipients =
                    fixture.realRecipientsInWireOrder(
                            original,
                            List.of(fixture.first, fixture.second, fixture.third)
                    );
            RealRecipientPosition selected = realRecipients.get(0);
            RealRecipientPosition laterValid =
                    realRecipients.get(realRecipients.size() - 1);

            ObjectNode root = object(original);
            flipEncodedField((ObjectNode) root.withArray("recipients").get(
                    selected.wireIndex()
            ), "encrypted_key");
            recomputeAad(root);

            ProtocolException failure = assertUnsignedFailure(
                    ErrorCode.KEY_UNWRAP_FAILED,
                    () -> fixture.receiver().receive(fixture.request(
                            json(root),
                            List.of(laterValid.handle(), selected.handle())
                    ))
            );
            assertGenericKeyRecovery(failure);
        }
    }

    @Test
    void reorderedRecipientsWithFreshAadAndChangedIvCiphertextOrTagFailGcm() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.send(fixture.binaryPayload());

            ObjectNode reordered = object(original);
            ArrayNode recipients = reordered.withArray("recipients");
            JsonNode first = recipients.get(0).deepCopy();
            recipients.set(0, recipients.get(1).deepCopy());
            recipients.set(1, first);
            recomputeAad(reordered);
            assertUnsignedFailure(ErrorCode.GCM_AUTH_FAILED, () ->
                    fixture.receiver().receive(fixture.request(
                            json(reordered), List.of(fixture.second)
                    )));

            for (String field : List.of("iv", "ciphertext", "tag")) {
                ObjectNode root = object(original);
                flipEncodedField(root, field);
                assertUnsignedFailure(ErrorCode.GCM_AUTH_FAILED, () ->
                        fixture.receiver().receive(fixture.request(
                                json(root), List.of(fixture.second)
                        )));
            }
        }
    }

    @Test
    void realCekReencryptionWithWrongBindingReleasesNoUnsignedOrSignedResult() {
        try (Fixture fixture = new Fixture()) {
            String unsigned = fixture.send(fixture.binaryPayload());
            assertUnsignedFailure(ErrorCode.BINDING_FAILED, () ->
                    fixture.receiver().receive(fixture.request(
                            fixture.bindingFailure(unsigned),
                            List.of(fixture.second)
                    )));

            String signed = fixture.sendSigned(fixture.binaryPayload());
            AtomicInteger resolverCalls = new AtomicInteger();
            assertSignedFailure(ErrorCode.BINDING_FAILED, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.signedBindingFailure(signed),
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.second)
                    )));
            assertEquals(0, resolverCalls.get(),
                    "binding must fail before identity resolution");
        }
    }

    @Test
    void realReencryptedSignedMutationsFailAtSignatureOrTrustWithoutIdentity() {
        try (Fixture fixture = new Fixture()) {
            String original = fixture.sendSigned(fixture.binaryPayload());

            assertSignedFailure(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedFlippedSignature(original),
                            kid -> Optional.of(fixture.trustedSigningKey()),
                            List.of(fixture.second)
                    )));

            AtomicInteger unknownResolverCalls = new AtomicInteger();
            AtomicReference<String> unknownRequestedKid = new AtomicReference<>();
            assertSignedFailure(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedUnknownSigner(original),
                            kid -> {
                                unknownResolverCalls.incrementAndGet();
                                unknownRequestedKid.set(kid);
                                return Optional.empty();
                            },
                            List.of(fixture.second)
                    )));
            assertEquals(1, unknownResolverCalls.get());
            assertEquals(fixture.unrelatedSigningKid,
                    unknownRequestedKid.get());

            for (String segment : List.of("protected", "payload")) {
                assertSignedFailure(ErrorCode.SIGNATURE_INVALID, () ->
                        fixture.signedReceiver().receive(fixture.signedRequest(
                                fixture.authenticatedChangedSignedSegment(
                                        original, segment
                                ),
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(fixture.second)
                        )));
            }
        }
    }

    private static ProtocolException assertUnsignedFailure(
            ErrorCode expected,
            Supplier<ObfuscationX25519UnsignedReceiver.Result> operation
    ) {
        AtomicReference<ObfuscationX25519UnsignedReceiver.Result> released =
                new AtomicReference<>();
        ProtocolException failure = assertThrows(
                ProtocolException.class,
                () -> released.set(operation.get())
        );
        assertEquals(expected, failure.errorCode());
        assertNull(released.get(), "failure must not release a payload result");
        return failure;
    }

    private static ProtocolException assertSignedFailure(
            ErrorCode expected,
            Supplier<ObfuscationX25519SignedReceiver.Result> operation
    ) {
        AtomicReference<ObfuscationX25519SignedReceiver.Result> released =
                new AtomicReference<>();
        ProtocolException failure = assertThrows(
                ProtocolException.class,
                () -> released.set(operation.get())
        );
        assertEquals(expected, failure.errorCode());
        assertNull(released.get(),
                "failure must not release payload or authenticated identity");
        return failure;
    }

    private static void assertGenericKeyRecovery(ProtocolException failure) {
        assertEquals(ErrorCode.KEY_UNWRAP_FAILED, failure.errorCode());
        assertEquals("obfuscation recipient key recovery failed",
                failure.getMessage());
        assertNull(failure.getCause());
    }
}
