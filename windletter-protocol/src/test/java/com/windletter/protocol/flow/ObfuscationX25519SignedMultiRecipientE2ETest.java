package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519SignedMultiRecipientE2ETest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("representativeBuckets")
    void realBouncyCastleRepresentativeBucketsAuthenticateFinalWireOrderAndSigner(
            BucketCase testCase
    ) {
        try (Fixture fixture = new Fixture()) {
            List<X25519PrivateKeyHandle> handles =
                    fixture.newRecipientHandles(testCase.realRecipients());
            try {
                ProtocolPayload payload = payload(fixture, testCase.payloadKind());
                String wire = fixture.sendSigned(payload, handles);
                assertWireShapeAndAad(wire, testCase.bucket());

                List<RealRecipientPosition> realRecipients =
                        fixture.realRecipientsInWireOrder(wire, handles);
                List<RealRecipientPosition> receivers = testCase.checkFirstMiddleLast()
                        ? List.of(
                                realRecipients.get(0),
                                realRecipients.get(realRecipients.size() / 2),
                                realRecipients.get(realRecipients.size() - 1)
                        )
                        : List.of(realRecipients.get(realRecipients.size() / 2));

                for (RealRecipientPosition recipient : receivers) {
                    ObfuscationX25519SignedReceiver.Result result =
                            fixture.signedReceiver().receive(fixture.signedRequest(
                                    wire,
                                    kid -> Optional.of(fixture.trustedSigningKey()),
                                    List.of(recipient.handle())
                            ));
                    assertPayload(payload, result.payload());
                    assertEquals(MESSAGE_ID, result.messageId());
                    assertEquals(TIMESTAMP, result.timestamp());
                    assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                            result.authenticationStatus());
                    assertEquals(IDENTITY_ID,
                            result.authenticatedSender().identityId());
                    assertEquals(fixture.signingKid,
                            result.authenticatedSender().signingKid());
                }

                assertCode(ErrorCode.NOT_FOR_ME, () ->
                        fixture.signedReceiver().receive(fixture.signedRequest(
                                wire,
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(fixture.unrelated)
                        )));
            } finally {
                closeHandles(handles);
            }
        }
    }

    static Stream<BucketCase> representativeBuckets() {
        return Stream.of(
                new BucketCase(3, 8, PayloadKind.TEXT, false),
                new BucketCase(9, 16, PayloadKind.EMPTY, false),
                new BucketCase(17, 32, PayloadKind.BINARY, true)
        );
    }

    private static ProtocolPayload payload(Fixture fixture, PayloadKind kind) {
        return switch (kind) {
            case BINARY -> fixture.binaryPayload();
            case TEXT -> fixture.textPayload();
            case EMPTY -> fixture.emptyPayload();
        };
    }

    private static void assertPayload(
            ProtocolPayload expected,
            ProtocolPayload actual
    ) {
        byte[] testOwnedExpected = expected.data();
        byte[] testOwnedActual = actual.data();
        try {
            assertEquals(expected.contentType(), actual.contentType());
            assertArrayEquals(testOwnedExpected, testOwnedActual);
            assertEquals(expected.originalSize(), actual.originalSize());
        } finally {
            clear(testOwnedExpected);
            clear(testOwnedActual);
        }
    }

    private static void assertWireShapeAndAad(String wire, int expectedBucket) {
        ObjectNode root = object(wire);
        ArrayNode recipients = (ArrayNode) root.get("recipients");
        assertEquals(expectedBucket, recipients.size());
        for (JsonNode value : recipients) {
            assertEquals(Set.of("rid", "encrypted_key"),
                    fieldNames((ObjectNode) value));
            byte[] testOwnedRid = null;
            byte[] testOwnedEncryptedKey = null;
            try {
                testOwnedRid = Base64Url.decodeCanonical(
                        value.get("rid").textValue(), "test.rid"
                );
                testOwnedEncryptedKey = Base64Url.decodeCanonical(
                        value.get("encrypted_key").textValue(),
                        "test.encrypted_key"
                );
                assertEquals(16, testOwnedRid.length);
                assertEquals(40, testOwnedEncryptedKey.length);
                assertFalse(value.has("ek"));
            } finally {
                clear(testOwnedRid);
                clear(testOwnedEncryptedKey);
            }
        }

        byte[] testOwnedProtected = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        try {
            ObjectNode header = object(new String(
                    testOwnedProtected, StandardCharsets.UTF_8
            ));
            assertEquals("wind+jws", header.get("cty").textValue());
            assertEquals("obfuscation", header.get("wind_mode").textValue());
            assertEquals("X25519", header.get("key_alg").textValue());
            assertTrue(header.has("epk"));
            assertFalse(header.has("kid"));
        } finally {
            clear(testOwnedProtected);
        }

        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
    }

    private static Set<String> fieldNames(ObjectNode node) {
        HashSet<String> names = new HashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private enum PayloadKind { BINARY, TEXT, EMPTY }

    record BucketCase(
            int realRecipients,
            int bucket,
            PayloadKind payloadKind,
            boolean checkFirstMiddleLast
    ) {
        @Override
        public String toString() {
            return realRecipients + " real -> " + bucket + " entries, "
                    + payloadKind.name().toLowerCase();
        }
    }
}
