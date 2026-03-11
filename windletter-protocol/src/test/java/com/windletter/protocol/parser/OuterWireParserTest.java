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

        assertEquals("cA", message.protectedB64());
        assertEquals("YWE", message.aadB64());
        assertEquals("aXY", message.ivB64());
        assertEquals("Y3Q", message.ciphertextB64());
        assertEquals("dGFn", message.tagB64());
        assertEquals(1, message.recipients().size());

        RecipientEntry recipient = message.recipients().get(0);
        assertNotNull(recipient.kid());
        assertEquals("a2lkZWNj", recipient.kid().x25519());
        assertEquals("a2lkcHE", recipient.kid().mlkem768());
        assertEquals("cmlkMQ", recipient.rid());
        assertEquals("ZWsx", recipient.ek());
        assertEquals("d3JhcHBlZA", recipient.encryptedKey());
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
        assertEquals("cA", message.protectedB64());
    }

    @Test
    void shouldThrowInvalidFieldWhenRequiredFieldMissing() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("""
            {
              "protected":"cA",
              "aad":"YWE",
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q"
            }
            """));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldThrowInvalidFieldWhenTopLevelFieldTypeWrong() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("""
            {
              "protected":"cA",
              "aad":123,
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldThrowInvalidFieldWhenProtectedIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"protected\":\"cA\"", "\"protected\":\"abc+\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenAadIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"aad\":\"YWE\"", "\"aad\":\"abc=\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenIvIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"iv\":\"aXY\"", "\"iv\":\"ab c\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenCiphertextIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"ciphertext\":\"Y3Q\"", "\"ciphertext\":\"a/b\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenTagIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"tag\":\"dGFn\"", "\"tag\":\"abc=\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenTagBase64UrlLengthMod4IsOne() {
        assertInvalidField(validWireJson().replace("\"tag\":\"dGFn\"", "\"tag\":\"abcde\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenTopLevelFieldUnknown() {
        assertInvalidField(validWireJson().replace("\"tag\":\"dGFn\"", "\"tag\":\"dGFn\",\"extra\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenRecipientFieldUnknown() {
        assertInvalidField(validWireJson().replace(
            "\"encrypted_key\":\"d3JhcHBlZA\"",
            "\"encrypted_key\":\"d3JhcHBlZA\",\"unknown\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidFieldUnknown() {
        assertInvalidField(validWireJson().replace(
            "\"mlkem768\":\"a2lkcHE\"",
            "\"mlkem768\":\"a2lkcHE\",\"unknown\":\"x\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenRidIsNull() {
        assertInvalidField(validWireJson().replace("\"rid\":\"cmlkMQ\"", "\"rid\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenRidIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"rid\":\"cmlkMQ\"", "\"rid\":\"ab+\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenRidBase64UrlLengthMod4IsOne() {
        assertInvalidField(validWireJson().replace("\"rid\":\"cmlkMQ\"", "\"rid\":\"abcde\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenEkIsNull() {
        assertInvalidField(validWireJson().replace("\"ek\":\"ZWsx\"", "\"ek\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEkIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"ek\":\"ZWsx\"", "\"ek\":\"a/b\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyIsNull() {
        assertInvalidField(validWireJson().replace("\"encrypted_key\":\"d3JhcHBlZA\"", "\"encrypted_key\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyMissing() {
        assertInvalidField("""
            {
              "protected":"cA",
              "aad":"YWE",
              "recipients":[
                {
                  "kid":{
                    "x25519":"a2lkZWNj",
                    "mlkem768":"a2lkcHE"
                  },
                  "rid":"cmlkMQ",
                  "ek":"ZWsx"
                }
              ],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """);
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyTypeWrong() {
        assertInvalidField(validWireJson().replace("\"encrypted_key\":\"d3JhcHBlZA\"", "\"encrypted_key\":123"));
    }

    @Test
    void shouldThrowInvalidFieldWhenEncryptedKeyIsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"encrypted_key\":\"d3JhcHBlZA\"", "\"encrypted_key\":\"a/b\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidIsNull() {
        assertInvalidField("""
            {
              "protected":"cA",
              "aad":"YWE",
              "recipients":[
                {
                  "kid":null,
                  "rid":"cmlkMQ",
                  "ek":"ZWsx",
                  "encrypted_key":"d3JhcHBlZA"
                }
              ],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """);
    }

    @Test
    void shouldThrowInvalidFieldWhenKidX25519IsNull() {
        assertInvalidField(validWireJson().replace("\"x25519\":\"a2lkZWNj\"", "\"x25519\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidX25519IsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"x25519\":\"a2lkZWNj\"", "\"x25519\":\"kid=\""));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidMlkem768IsNull() {
        assertInvalidField(validWireJson().replace("\"mlkem768\":\"a2lkcHE\"", "\"mlkem768\":null"));
    }

    @Test
    void shouldThrowInvalidFieldWhenKidMlkem768IsNotBase64Url() {
        assertInvalidField(validWireJson().replace("\"mlkem768\":\"a2lkcHE\"", "\"mlkem768\":\"kid pq\""));
    }

    @Test
    void shouldThrowMalformedWireWhenTopLevelFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"cA",
              "aad":"YWE",
              "aad":"aad-dup",
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """);
    }

    @Test
    void shouldThrowMalformedWireWhenRecipientFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"cA",
              "aad":"YWE",
              "recipients":[
                {
                  "rid":"cmlkMQ",
                  "rid":"rid-2"
                }
              ],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """);
    }

    @Test
    void shouldThrowMalformedWireWhenKidFieldDuplicated() {
        assertMalformed("""
            {
              "protected":"cA",
              "aad":"YWE",
              "recipients":[
                {
                  "kid":{
                    "x25519":"kid-1",
                    "x25519":"kid-2"
                  }
                }
              ],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """);
    }

    @Test
    void shouldUseStrictDuplicateDetectionWhenObjectMapperInjected() throws Exception {
        ObjectMapper injectedMapper = new ObjectMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(injectedMapper);
        String duplicateOuter = """
            {
              "protected":"cA",
              "aad":"YWE",
              "aad":"aad-dup",
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
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
            injectedParser.parse(validWireJson().replace("\"tag\":\"dGFn\"", "\"tag\":\"dGFn\",\"extra\":\"x\"")));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldRejectSingleQuotesWhenLenientObjectMapperInjected() throws Exception {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String singleQuotesJson = "{'protected':'cA','aad':'YWE','recipients':[],'iv':'aXY','ciphertext':'Y3Q','tag':'dGFn'}";

        JsonNode lenientNode = lenientMapper.readTree(singleQuotesJson);
        assertEquals("YWE", lenientNode.get("aad").textValue());
        assertMalformedWithParser(injectedParser, singleQuotesJson);
    }

    @Test
    void shouldRejectCommentsWhenLenientObjectMapperInjected() {
        ObjectMapper lenientMapper = newLenientMapper();
        OuterWireParser injectedParser = new JacksonOuterWireParser(lenientMapper);
        String commentJson = """
            {
              "protected":"cA",
              // comment
              "aad":"YWE",
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
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
              "protected":"cA",
              "aad":"YWE",
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn",
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
              "protected":"cA",
              "aad":+1,
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
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
              "protected":"cA",
              "aad":.5,
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
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
              "protected":"cA",
              "aad":1.,
              "recipients":[],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
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
              "protected":"cA",
              "aad":"YWE",
              "recipients":[
                {
                  "kid":{
                    "x25519":"a2lkZWNj",
                    "mlkem768":"a2lkcHE"
                  },
                  "rid":"cmlkMQ",
                  "ek":"ZWsx",
                  "encrypted_key":"d3JhcHBlZA"
                }
              ],
              "iv":"aXY",
              "ciphertext":"Y3Q",
              "tag":"dGFn"
            }
            """;
    }
}

