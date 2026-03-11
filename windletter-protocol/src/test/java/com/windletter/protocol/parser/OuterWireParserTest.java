package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.RecipientEntry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OuterWireParserTest {

    private final OuterWireParser parser = new JacksonOuterWireParser();

    @Test
    void shouldParseValidWireMessage() {
        OuterWireMessage message = parser.parse(validWireJson());

        assertEquals("p-b64", message.protectedB64());
        assertEquals("aad-b64", message.aadB64());
        assertEquals("iv-b64", message.ivB64());
        assertEquals("ct-b64", message.ciphertextB64());
        assertEquals("tag-b64", message.tagB64());
        assertEquals(1, message.recipients().size());

        RecipientEntry recipient = message.recipients().get(0);
        assertNotNull(recipient.kid());
        assertEquals("kid-ecc", recipient.kid().x25519());
        assertEquals("kid-pq", recipient.kid().mlkem768());
        assertEquals("rid-1", recipient.rid());
        assertEquals("ek-1", recipient.ek());
        assertEquals("wrapped-1", recipient.encryptedKey());
    }

    @Test
    void shouldThrowMalformedWireForInvalidJson() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("{"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldThrowMalformedWireForEmptyJson() {
        assertMalformed("");
    }

    @Test
    void shouldThrowMalformedWireForBlankJson() {
        assertMalformed("   \n\t  ");
    }

    @Test
    void shouldThrowMalformedWireWhenRootIsNotObject() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("[]"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldThrowMalformedWireWhenTrailingObjectExists() {
        assertMalformed(validWireJson() + "{\"junk\":1}");
    }

    @Test
    void shouldThrowMalformedWireWhenTrailingNumberExists() {
        assertMalformed(validWireJson() + "123");
    }

    @Test
    void shouldThrowMalformedWireWhenTrailingArrayExists() {
        assertMalformed(validWireJson() + "[]");
    }

    @Test
    void shouldAllowTrailingWhitespaceOnly() {
        OuterWireMessage message = parser.parse(validWireJson() + " \n\t ");
        assertEquals("p-b64", message.protectedB64());
    }

    @Test
    void shouldThrowInvalidFieldWhenRequiredFieldMissing() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64"
            }
            """));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldThrowInvalidFieldWhenTopLevelFieldTypeWrong() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("""
            {
              "protected":"p-b64",
              "aad":123,
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldThrowInvalidFieldWhenTopLevelFieldUnknown() {
        assertInvalidField(validWireJson().replace("\"tag\":\"tag-b64\"", "\"tag\":\"tag-b64\",\"extra\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenRecipientFieldUnknown() {
        assertInvalidField(validWireJson().replace(
            "\"encrypted_key\":\"wrapped-1\"",
            "\"encrypted_key\":\"wrapped-1\",\"unknown\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidFieldUnknown() {
        assertInvalidField(validWireJson().replace(
            "\"mlkem768\":\"kid-pq\"",
            "\"mlkem768\":\"kid-pq\",\"unknown\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenRidIsNull() {
        assertInvalidField(validWireJson().replace("\"rid\":\"rid-1\"", "\"rid\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEkIsNull() {
        assertInvalidField(validWireJson().replace("\"ek\":\"ek-1\"", "\"ek\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyIsNull() {
        assertInvalidField(validWireJson().replace("\"encrypted_key\":\"wrapped-1\"", "\"encrypted_key\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyMissing() {
        assertInvalidField("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[
                {
                  "kid":{
                    "x25519":"kid-ecc",
                    "mlkem768":"kid-pq"
                  },
                  "rid":"rid-1",
                  "ek":"ek-1"
                }
              ],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """);
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyTypeWrong() {
        assertInvalidField(validWireJson().replace("\"encrypted_key\":\"wrapped-1\"", "\"encrypted_key\":123"));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidIsNull() {
        assertInvalidField("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[
                {
                  "kid":null,
                  "rid":"rid-1",
                  "ek":"ek-1",
                  "encrypted_key":"wrapped-1"
                }
              ],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """);
    }

    @Test
    void shouldThrowInvalidFieldWhenKidX25519IsNull() {
        assertInvalidField(validWireJson().replace("\"x25519\":\"kid-ecc\"", "\"x25519\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidMlkem768IsNull() {
        assertInvalidField(validWireJson().replace("\"mlkem768\":\"kid-pq\"", "\"mlkem768\":null"));
    }

    @Test
    void shouldThrowMalformedWireWhenTopLevelFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "aad":"aad-dup",
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """);
    }

    @Test
    void shouldThrowMalformedWireWhenRecipientFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[
                {
                  "rid":"rid-1",
                  "rid":"rid-2"
                }
              ],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """);
    }

    @Test
    void shouldThrowMalformedWireWhenKidFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[
                {
                  "kid":{
                    "x25519":"kid-1",
                    "x25519":"kid-2"
                  }
                }
              ],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """);
    }

    @Test
    void shouldUseStrictDuplicateDetectionWhenObjectMapperInjected() throws Exception {
        ObjectMapper injectedMapper = new ObjectMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(injectedMapper);
        String duplicateOuter = """
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "aad":"aad-dup",
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;

        ProtocolException ex = assertThrows(ProtocolException.class, () -> injectedParser.parse(duplicateOuter));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());

        JsonNode node = injectedMapper.readTree(duplicateOuter);
        assertEquals("aad-dup", node.get("aad").textValue());
    }

    @Test
    void shouldRejectUnknownFieldWhenObjectMapperInjected() {
        ObjectMapper injectedMapper = new ObjectMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(injectedMapper);

        ProtocolException ex = assertThrows(ProtocolException.class, () ->
            injectedParser.parse(validWireJson().replace("\"tag\":\"tag-b64\"", "\"tag\":\"tag-b64\",\"extra\":\"x\"")));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldRejectSingleQuotesWhenLenientObjectMapperInjected() throws Exception {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String singleQuotesJson = "{'protected':'p-b64','aad':'aad-b64','recipients':[],'iv':'iv-b64','ciphertext':'ct-b64','tag':'tag-b64'}";

        JsonNode lenientNode = lenientMapper.readTree(singleQuotesJson);
        assertEquals("aad-b64", lenientNode.get("aad").textValue());
        assertMalformedWithParser(injectedParser, singleQuotesJson);
    }

    @Test
    void shouldRejectCommentsWhenLenientObjectMapperInjected() {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String commentJson = """
            {
              "protected":"p-b64",
              // comment
              "aad":"aad-b64",
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;

        assertMalformedWithParser(injectedParser, commentJson);
    }

    @Test
    void shouldRejectTrailingCommaWhenLenientObjectMapperInjected() {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String trailingCommaJson = """
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64",
            }
            """;

        assertMalformedWithParser(injectedParser, trailingCommaJson);
    }

    @Test
    void shouldRejectLeadingPlusNumberWhenLenientObjectMapperInjected() throws Exception {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String leadingPlusJson = """
            {
              "protected":"p-b64",
              "aad":+1,
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;

        JsonNode lenientNode = lenientMapper.readTree(leadingPlusJson);
        assertEquals(1, lenientNode.get("aad").intValue());
        assertMalformedWithParser(injectedParser, leadingPlusJson);
    }

    @Test
    void shouldRejectLeadingDecimalPointNumberWhenLenientObjectMapperInjected() throws Exception {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String leadingDecimalJson = """
            {
              "protected":"p-b64",
              "aad":.5,
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;

        JsonNode lenientNode = lenientMapper.readTree(leadingDecimalJson);
        assertEquals(0.5d, lenientNode.get("aad").doubleValue(), 0.0d);
        assertMalformedWithParser(injectedParser, leadingDecimalJson);
    }

    @Test
    void shouldRejectTrailingDecimalPointNumberWhenLenientObjectMapperInjected() throws Exception {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String trailingDecimalJson = """
            {
              "protected":"p-b64",
              "aad":1.,
              "recipients":[],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;

        JsonNode lenientNode = lenientMapper.readTree(trailingDecimalJson);
        assertEquals(1.0d, lenientNode.get("aad").doubleValue(), 0.0d);
        assertMalformedWithParser(injectedParser, trailingDecimalJson);
    }

    private void assertInvalidField(String wireJson) {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wireJson));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    private void assertMalformed(String wireJson) {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wireJson));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    private void assertMalformedWithParser(OuterWireParser parserToUse, String wireJson) {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parserToUse.parse(wireJson));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    private static ObjectMapper newLenientMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.getFactory().enable(JsonReadFeature.ALLOW_SINGLE_QUOTES.mappedFeature());
        mapper.getFactory().enable(JsonReadFeature.ALLOW_JAVA_COMMENTS.mappedFeature());
        mapper.getFactory().enable(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature());
        mapper.getFactory().enable(JsonReadFeature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().enable(JsonReadFeature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().enable(JsonReadFeature.ALLOW_TRAILING_DECIMAL_POINT_FOR_NUMBERS.mappedFeature());
        return mapper;
    }

    private static String validWireJson() {
        return """
            {
              "protected":"p-b64",
              "aad":"aad-b64",
              "recipients":[
                {
                  "kid":{
                    "x25519":"kid-ecc",
                    "mlkem768":"kid-pq"
                  },
                  "rid":"rid-1",
                  "ek":"ek-1",
                  "encrypted_key":"wrapped-1"
                }
              ],
              "iv":"iv-b64",
              "ciphertext":"ct-b64",
              "tag":"tag-b64"
            }
            """;
    }
}
