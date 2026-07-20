package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519UnsignedMultiRecipientE2ETest {

    @Test
    void realBouncyCastleThreeRecipientMessageHasEightRawEntriesAndAnyRecipientRecoversBinary() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.send(fixture.binaryPayload());
            ObjectNode root = object(wire);
            assertEquals(Set.of("protected", "aad", "recipients", "iv", "ciphertext", "tag"),
                    fieldNames(root));
            ArrayNode recipients = (ArrayNode) root.get("recipients");
            assertEquals(8, recipients.size());
            for (JsonNode value : recipients) {
                assertEquals(Set.of("rid", "encrypted_key"), fieldNames((ObjectNode) value));
                assertEquals(16, Base64Url.decodeCanonical(
                        value.get("rid").textValue(), "test.rid").length);
                assertEquals(40, Base64Url.decodeCanonical(
                        value.get("encrypted_key").textValue(), "test.encrypted_key").length);
            }
            byte[] protectedBytes = Base64Url.decodeCanonical(
                    root.get("protected").textValue(), "test.protected");
            try {
                ObjectNode header = object(new String(protectedBytes, StandardCharsets.UTF_8));
                assertEquals("obfuscation", header.get("wind_mode").textValue());
                assertEquals("X25519", header.get("key_alg").textValue());
                assertTrue(header.has("epk"));
                assertFalse(header.has("kid"));
            } finally {
                clear(protectedBytes);
            }

            for (X25519PrivateKeyHandle handle : List.of(
                    fixture.first, fixture.second, fixture.third)) {
                ObfuscationX25519UnsignedReceiver.Result result = fixture.receiver().receive(
                        fixture.request(wire, List.of(handle)));
                assertArrayEquals(BINARY, result.payload().data());
                assertEquals(MESSAGE_ID, result.messageId());
                assertEquals(TIMESTAMP, result.timestamp());
                assertEquals(32, handle.publicKey().length);
            }
        }
    }

    @Test
    void textAndEmptyPayloadsRoundTripAndUnrelatedKeyIsNotForMe() {
        try (Fixture fixture = new Fixture()) {
            for (ProtocolPayload payload : List.of(fixture.textPayload(), fixture.emptyPayload())) {
                String wire = fixture.send(payload);
                ObfuscationX25519UnsignedReceiver.Result result = fixture.receiver().receive(
                        fixture.request(wire, List.of(fixture.third)));
                assertEquals(payload.contentType(), result.payload().contentType());
                assertArrayEquals(payload.data(), result.payload().data());
                assertEquals(payload.originalSize(), result.payload().originalSize());
                assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                        fixture.request(wire, List.of(fixture.unrelated))));
            }
            assertEquals(32, fixture.third.publicKey().length);
            assertEquals(32, fixture.unrelated.publicKey().length);
        }
    }

    private static Set<String> fieldNames(ObjectNode node) {
        java.util.HashSet<String> names = new java.util.HashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
