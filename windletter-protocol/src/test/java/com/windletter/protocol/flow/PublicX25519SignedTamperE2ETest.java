package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.flipEncodedField;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.parseObject;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.recomputeAad;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.reencodeProtectedWithWhitespace;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.write;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicX25519SignedTamperE2ETest {

    @Test
    void authenticatedWrongBindingFailsBeforeTrustedSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            for (ProtocolFlowTestFixtures.BindingTarget target
                    : ProtocolFlowTestFixtures.BindingTarget.values()) {
                String maliciousWire = fixture.authenticatedBindingTamper(target);
                AtomicInteger signingResolverCalls = new AtomicInteger();

                assertProtocolCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                        fixture.receiveRequest(maliciousWire, fixture.secondRecipient, kid -> {
                            signingResolverCalls.incrementAndGet();
                            return java.util.Optional.of(fixture.trustedSigningKey());
                        })
                ));
                assertEquals(0, signingResolverCalls.get());
            }
        }
    }

    @Test
    void authenticatedFlippedSignatureIsRejectedByRealEd25519Verification() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String maliciousWire = fixture.authenticatedFlippedSignature();

            assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver().receive(
                    fixture.receiveRequest(maliciousWire, fixture.secondRecipient)
            ));
        }
    }

    @Test
    void changedProtectedOrPayloadSegmentWithoutResigningIsRejectedByExactVerification() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            for (String segment : List.of("protected", "payload")) {
                String maliciousWire = fixture.authenticatedChangedSegment(segment);

                assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver().receive(
                        fixture.receiveRequest(maliciousWire, fixture.secondRecipient)
                ));
            }
        }
    }

    @Test
    void validSignatureFromAnUnknownRealEd25519KeyDoesNotReleaseIdentityOrPayload() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String maliciousWire = fixture.authenticatedUnknownSigner();

            assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.receiver().receive(
                    fixture.receiveRequest(maliciousWire, fixture.secondRecipient)
            ));
        }
    }

    @Test
    void signedOuterRejectsAuthenticatedUnsignedInnerBeforeTrustedSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String maliciousWire = fixture.authenticatedUnsignedInner();
            assertInvalidInnerBeforeSigningResolution(fixture, maliciousWire);
        }
    }

    @Test
    void signedInnerTypAndAlgorithmAreStrictBeforeTrustedSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            for (String maliciousWire : List.of(
                    fixture.authenticatedWrongProtectedField("typ", "wind+inner"),
                    fixture.authenticatedWrongProtectedField("alg", "ES256")
            )) {
                assertInvalidInnerBeforeSigningResolution(fixture, maliciousWire);
            }
        }
    }

    @Test
    void signedInnerMissingAndExtraRootFieldsAreStrictBeforeTrustedSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            for (String maliciousWire : List.of(
                    fixture.authenticatedMissingRootField("signature"),
                    fixture.authenticatedExtraRootField()
            )) {
                assertInvalidInnerBeforeSigningResolution(fixture, maliciousWire);
            }
        }
    }

    @Test
    void signedInnerKidAndSignatureLengthsAreStrictBeforeTrustedSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            for (String maliciousWire : List.of(
                    fixture.authenticatedBadKidLength(31),
                    fixture.authenticatedBadKidLength(33),
                    fixture.authenticatedBadSignatureLength(63),
                    fixture.authenticatedBadSignatureLength(65)
            )) {
                assertInvalidInnerBeforeSigningResolution(fixture, maliciousWire);
            }
        }
    }

    @Test
    void changedRecipientContentOrOrderWithStaleAadFailsBeforeRoutingAndSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String wireJson = fixture.send(fixture.binaryPayload());

            ObjectNode contentChanged = parseObject(wireJson);
            ObjectNode target = (ObjectNode) contentChanged.withArray("recipients").get(1);
            flipEncodedField(target, "encrypted_key");
            assertOuterFailureBeforeSigningResolution(
                    fixture, write(contentChanged), ErrorCode.AAD_MISMATCH
            );

            ObjectNode orderChanged = parseObject(wireJson);
            ArrayNode recipients = orderChanged.withArray("recipients");
            JsonNode first = recipients.get(0).deepCopy();
            recipients.set(0, recipients.get(1).deepCopy());
            recipients.set(1, first);
            assertOuterFailureBeforeSigningResolution(
                    fixture, write(orderChanged), ErrorCode.AAD_MISMATCH
            );
        }
    }

    @Test
    void changedAadFailsBeforeRoutingAndSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            flipEncodedField(root, "aad");

            assertOuterFailureBeforeSigningResolution(
                    fixture, write(root), ErrorCode.AAD_MISMATCH
            );
        }
    }

    @Test
    void semanticallyIdenticalProtectedReencodingFailsGcmBeforeSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            reencodeProtectedWithWhitespace(root);

            assertOuterFailureBeforeSigningResolution(
                    fixture, write(root), ErrorCode.GCM_AUTH_FAILED
            );
        }
    }

    @Test
    void changedTargetEncryptedKeyWithRecomputedAadFailsUnwrapBeforeSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(1);
            flipEncodedField(target, "encrypted_key");
            recomputeAad(root);

            assertOuterFailureBeforeSigningResolution(
                    fixture, write(root), ErrorCode.KEY_UNWRAP_FAILED
            );
        }
    }

    @Test
    void changedIvCiphertextOrTagFailsGcmBeforeSigningResolution() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String wireJson = fixture.send(fixture.binaryPayload());
            for (String field : List.of("iv", "ciphertext", "tag")) {
                ObjectNode root = parseObject(wireJson);
                flipEncodedField(root, field);

                assertOuterFailureBeforeSigningResolution(
                        fixture, write(root), ErrorCode.GCM_AUTH_FAILED
                );
            }
        }
    }

    private static void assertInvalidInnerBeforeSigningResolution(
            SignedProtocolFlowTestFixtures fixture,
            String wireJson
    ) {
        AtomicInteger resolverCalls = new AtomicInteger();
        assertProtocolCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                fixture.receiveRequest(wireJson, fixture.secondRecipient, kid -> {
                    resolverCalls.incrementAndGet();
                    return java.util.Optional.of(fixture.trustedSigningKey());
                })
        ));
        assertEquals(0, resolverCalls.get());
    }

    private static void assertOuterFailureBeforeSigningResolution(
            SignedProtocolFlowTestFixtures fixture,
            String wireJson,
            ErrorCode expected
    ) {
        AtomicInteger signingResolverCalls = new AtomicInteger();
        assertProtocolCode(expected, () -> fixture.receiver().receive(
                fixture.receiveRequest(wireJson, fixture.secondRecipient, kid -> {
                    signingResolverCalls.incrementAndGet();
                    return java.util.Optional.of(fixture.trustedSigningKey());
                })
        ));
        assertEquals(0, signingResolverCalls.get());
    }
}
