package com.windletter.protocol.wire;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.parser.OuterWireParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OuterWireParserTest {

    private final OuterWireParser parser = new JacksonOuterWireParser();

    @Test
    void shouldParseValidOuterWireJson() {
        String wireJson = """
                {
                  "protected": "eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad": "W3siZW5jcnlwdGVkX2tleSI6ImVuYzEifV0",
                  "recipients": [
                    {"encrypted_key":"enc1"}
                  ],
                  "iv": "aXY",
                  "ciphertext": "Y3Q",
                  "tag": "dGFn"
                }
                """;

        OuterWireMessage wire = parser.parse(wireJson);

        assertEquals("aXY", wire.ivB64());
        assertEquals("Y3Q", wire.ciphertextB64());
        assertEquals("dGFn", wire.tagB64());
        assertEquals(1, wire.recipients().size());
        assertEquals("enc1", wire.recipients().get(0).encryptedKey());
    }

    @Test
    void shouldThrowMalformedWireWhenJsonInvalid() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("{"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldPreserveRawRecipientsNodeFromSameParse() {
        String wireJson = """
                {
                  "protected": "eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad": "W3siZW5jcnlwdGVkX2tleSI6ImVuYzEifV0",
                  "recipients": [
                    {"encrypted_key":"enc1"}
                  ],
                  "iv": "aXY",
                  "ciphertext": "Y3Q",
                  "tag": "dGFn"
                }
                """;

        ParsedOuterWire parsed = parser.parseWithRaw(wireJson);

        assertEquals(1, parsed.recipientsNode().size());
        assertFalse(parsed.recipientsNode().get(0).has("ek"));
        assertFalse(parsed.recipientsNode().get(0).has("rid"));
    }

    @Test
    void shouldKeepParseAndParseWithRawStructurallyConsistent() {
        String wireJson = """
                {
                  "protected": "eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad": "W3siZW5jcnlwdGVkX2tleSI6ImVuYzEifV0",
                  "recipients": [
                    {"encrypted_key":"enc1"}
                  ],
                  "iv": "aXY",
                  "ciphertext": "Y3Q",
                  "tag": "dGFn"
                }
                """;

        OuterWireMessage parsed = parser.parse(wireJson);
        ParsedOuterWire parsedWithRaw = parser.parseWithRaw(wireJson);

        assertEquals(parsed, parsedWithRaw.wire());
    }

    @Test
    void shouldReturnInvalidFieldWhenTypeMismatched() {
        String wireJson = """
                {
                  "protected": "eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad": "W3siZW5jcnlwdGVkX2tleSI6ImVuYzEifV0",
                  "recipients": "not-an-array",
                  "iv": "aXY",
                  "ciphertext": "Y3Q",
                  "tag": "dGFn"
                }
                """;

        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wireJson));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldReturnMalformedWireWhenRootIsNotObject() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("[]"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldDistinguishMissingAndNullRecipientsInRawNode() {
        String missingRecipients = """
                {
                  "protected":"eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad":"W10",
                  "iv":"aXY",
                  "ciphertext":"Y3Q",
                  "tag":"dGFn"
                }
                """;
        String nullRecipients = """
                {
                  "protected":"eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad":"W10",
                  "recipients":null,
                  "iv":"aXY",
                  "ciphertext":"Y3Q",
                  "tag":"dGFn"
                }
                """;

        ParsedOuterWire missing = parser.parseWithRaw(missingRecipients);
        ParsedOuterWire explicitNull = parser.parseWithRaw(nullRecipients);

        assertNull(missing.recipientsNode());
        assertTrue(explicitNull.recipientsNode().isNull());
    }
}
