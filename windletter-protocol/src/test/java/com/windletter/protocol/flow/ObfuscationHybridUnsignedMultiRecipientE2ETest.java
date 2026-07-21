package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridUnsignedMultiRecipientE2ETest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("representativeBuckets")
    void realBouncyCastleRepresentativeBucketsAuthenticateFinalWireOrder(
            BucketCase testCase
    ) {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            List<ObfuscationHybridFlowTestFixtures.HybridPair> recipients =
                    fixture.newRecipientPairs(testCase.realRecipients());
            try {
                ProtocolPayload payload = payload(
                        fixture, testCase.payloadKind()
                );
                String wire = fixture.send(payload, recipients);
                assertWireShapeAndAad(wire, testCase.bucket());
                List<ObfuscationHybridFlowTestFixtures.RealRecipientPosition>
                        realRecipients = fixture.realRecipientsInWireOrder(
                        wire, recipients
                );

                for (ObfuscationHybridFlowTestFixtures.RealRecipientPosition recipient
                        : firstMiddleLast(realRecipients)) {
                    ObfuscationHybridUnsignedReceiver.Result result =
                            fixture.receiver().receive(fixture.request(
                                    wire,
                                    List.of(recipient.pair().privateKeys())
                            ));
                    assertPayload(payload, result.payload());
                    assertEquals(
                            ProtocolFlowTestFixtures.MESSAGE_ID,
                            result.messageId()
                    );
                    assertEquals(
                            ProtocolFlowTestFixtures.TIMESTAMP,
                            result.timestamp()
                    );
                    assertEquals(
                            ProtocolAuthenticationStatus.UNSIGNED,
                            result.authenticationStatus()
                    );
                }

                assertProtocolCode(ErrorCode.NOT_FOR_ME, () ->
                        fixture.receiver().receive(fixture.request(
                                wire,
                                List.of(fixture.unrelated.privateKeys())
                        ))
                );
            } finally {
                ObfuscationHybridFlowTestFixtures.closePairs(recipients);
            }
        }
    }

    static Stream<BucketCase> representativeBuckets() {
        return Stream.of(
                new BucketCase(1, 8, PayloadKind.BINARY),
                new BucketCase(16, 16, PayloadKind.TEXT),
                new BucketCase(17, 32, PayloadKind.EMPTY)
        );
    }

    private static ProtocolPayload payload(
            ObfuscationHybridFlowTestFixtures fixture,
            PayloadKind kind
    ) {
        return switch (kind) {
            case BINARY -> fixture.binaryPayload();
            case TEXT -> fixture.textPayload();
            case EMPTY -> fixture.emptyPayload();
        };
    }

    private static List<ObfuscationHybridFlowTestFixtures.RealRecipientPosition>
    firstMiddleLast(
            List<ObfuscationHybridFlowTestFixtures.RealRecipientPosition>
                    recipients
    ) {
        if (recipients.size() == 1) {
            return List.of(recipients.get(0));
        }
        return List.of(
                recipients.get(0),
                recipients.get(recipients.size() / 2),
                recipients.get(recipients.size() - 1)
        );
    }

    private static void assertPayload(
            ProtocolPayload expected,
            ProtocolPayload actual
    ) {
        byte[] expectedData = expected.data();
        byte[] actualData = actual.data();
        try {
            assertEquals(expected.contentType(), actual.contentType());
            assertArrayEquals(expectedData, actualData);
            assertEquals(expected.originalSize(), actual.originalSize());
        } finally {
            ObfuscationHybridFlowTestFixtures.clear(expectedData);
            ObfuscationHybridFlowTestFixtures.clear(actualData);
        }
    }

    private static void assertWireShapeAndAad(
            String wire,
            int expectedBucket
    ) {
        ObjectNode root = ProtocolFlowTestFixtures.parseObject(wire);
        assertEquals(
                Set.of("protected", "aad", "recipients", "iv", "ciphertext", "tag"),
                fieldNames(root)
        );
        ArrayNode recipients = root.withArray("recipients");
        assertEquals(expectedBucket, recipients.size());
        HashSet<String> rids = new HashSet<>();
        HashSet<String> encapsulationCiphertexts = new HashSet<>();
        for (JsonNode value : recipients) {
            ObjectNode recipient = (ObjectNode) value;
            assertEquals(Set.of("rid", "encrypted_key", "ek"), fieldNames(recipient));
            byte[] rid = Base64Url.decodeCanonical(
                    recipient.get("rid").textValue(), "test.rid"
            );
            byte[] encryptedKey = Base64Url.decodeCanonical(
                    recipient.get("encrypted_key").textValue(), "test.encrypted_key"
            );
            byte[] ek = Base64Url.decodeCanonical(
                    recipient.get("ek").textValue(), "test.ek"
            );
            try {
                assertEquals(16, rid.length);
                assertEquals(40, encryptedKey.length);
                assertEquals(1088, ek.length);
                assertTrue(rids.add(recipient.get("rid").textValue()));
                assertTrue(
                        encapsulationCiphertexts.add(
                                recipient.get("ek").textValue()
                        ),
                        "each real/decoy recipient entry must use an independent ek"
                );
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(rid);
                ObfuscationHybridFlowTestFixtures.clear(encryptedKey);
                ObfuscationHybridFlowTestFixtures.clear(ek);
            }
        }

        byte[] protectedBytes = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        try {
            ObjectNode header = ProtocolFlowTestFixtures.parseObject(
                    new String(protectedBytes, StandardCharsets.UTF_8)
            );
            assertEquals("obfuscation", header.get("wind_mode").textValue());
            assertEquals("X25519ML-KEM-768", header.get("key_alg").textValue());
            assertTrue(header.has("epk"));
            assertFalse(header.has("kid"));
        } finally {
            ObfuscationHybridFlowTestFixtures.clear(protectedBytes);
        }

        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
    }

    private static Set<String> fieldNames(ObjectNode node) {
        HashSet<String> fields = new HashSet<>();
        node.fieldNames().forEachRemaining(fields::add);
        return fields;
    }

    private enum PayloadKind { BINARY, TEXT, EMPTY }

    record BucketCase(
            int realRecipients,
            int bucket,
            PayloadKind payloadKind
    ) {
        @Override
        public String toString() {
            return realRecipients + " real -> " + bucket + " entries, "
                    + payloadKind.name().toLowerCase();
        }
    }
}
