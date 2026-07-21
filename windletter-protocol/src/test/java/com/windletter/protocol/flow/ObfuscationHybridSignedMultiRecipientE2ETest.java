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
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridSignedMultiRecipientE2ETest {

    @Test
    void threeRealPairsRestoreOneSignedBinaryWireAndAuthenticateTheSender() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            assertExactWireShape(wire);

            for (ObfuscationHybridFlowTestFixtures.HybridPair recipient
                    : fixture.recipients()) {
                ObfuscationHybridSignedReceiver.Result result =
                        fixture.signedReceiver().receive(fixture.signedRequest(
                                wire,
                                fixture.trustedSigningResolver(),
                                List.of(recipient.privateKeys())
                        ));
                assertPayload(fixture.binaryPayload(), result.payload());
                assertEquals(
                        ProtocolFlowTestFixtures.MESSAGE_ID,
                        result.messageId()
                );
                assertEquals(
                        ProtocolFlowTestFixtures.TIMESTAMP,
                        result.timestamp()
                );
                assertEquals(
                        ProtocolAuthenticationStatus.SIGNED_VALID,
                        result.authenticationStatus()
                );
                assertEquals(
                        ObfuscationHybridFlowTestFixtures.IDENTITY_ID,
                        result.authenticatedSender().identityId()
                );
                assertEquals(
                        fixture.signingKid,
                        result.authenticatedSender().signingKid()
                );
            }

            AtomicInteger resolverCalls = new AtomicInteger();
            assertProtocolCode(ErrorCode.NOT_FOR_ME, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            wire,
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.unrelated.privateKeys())
                    ))
            );
            assertEquals(0, resolverCalls.get());
        }
    }

    @Test
    void textAndEmptyPayloadsRoundTripThroughRealSignedHybridWires() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            for (ProtocolPayload payload : List.of(
                    fixture.textPayload(), fixture.emptyPayload()
            )) {
                String wire = fixture.sendSigned(payload);
                ObfuscationHybridSignedReceiver.Result result =
                        fixture.signedReceiver().receive(fixture.signedRequest(
                                wire,
                                fixture.trustedSigningResolver(),
                                List.of(fixture.middle.privateKeys())
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
                        ProtocolAuthenticationStatus.SIGNED_VALID,
                        result.authenticationStatus()
                );
            }
        }
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

    private static void assertExactWireShape(String wire) {
        ObjectNode root = ProtocolFlowTestFixtures.parseObject(wire);
        ArrayNode recipients = root.withArray("recipients");
        assertEquals(8, recipients.size());
        HashSet<String> rids = new HashSet<>();
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
            assertEquals("wind+jws", header.get("cty").textValue());
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
}
