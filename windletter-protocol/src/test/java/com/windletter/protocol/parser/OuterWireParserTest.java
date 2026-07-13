package com.windletter.protocol.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OuterWireParserTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private final OuterWireParser parser = new JacksonOuterWireParser();

    @Test
    void parsePublicX25519() {
        WindLetter parsed = parser.parse(toJson(validOuter("public", "X25519", "wind+jws")));
        assertEquals("public", parsed.protectedHeader().windMode());
        assertEquals("X25519", parsed.protectedHeader().keyAlg());
        assertInstanceOf(SenderKid.class, parsed.protectedHeader().senderInfo());
        assertInstanceOf(PublicRecipient.class, parsed.recipients().get(0));
    }

    @Test
    void parsePublicHybrid() {
        WindLetter parsed = parser.parse(toJson(validOuter("public", "X25519ML-KEM-768", "wind+inner")));
        assertEquals("public", parsed.protectedHeader().windMode());
        assertEquals("X25519ML-KEM-768", parsed.protectedHeader().keyAlg());
        assertInstanceOf(SenderKid.class, parsed.protectedHeader().senderInfo());
        RecipientEntry recipient = parsed.recipients().get(0);
        PublicRecipient publicRecipient = assertInstanceOf(PublicRecipient.class, recipient);
        assertEquals(1088, publicRecipient.ek().length);
    }

    @Test
    void parseObfuscationX25519() {
        WindLetter parsed = parser.parse(toJson(validOuter("obfuscation", "X25519", "wind+jws")));
        assertEquals("obfuscation", parsed.protectedHeader().windMode());
        assertEquals("X25519", parsed.protectedHeader().keyAlg());
        assertInstanceOf(Epk.class, parsed.protectedHeader().senderInfo());
        RecipientEntry recipient = parsed.recipients().get(0);
        ObfuscationRecipient obfuscationRecipient = assertInstanceOf(ObfuscationRecipient.class, recipient);
        assertEquals(null, obfuscationRecipient.ek());
    }

    @Test
    void parseObfuscationHybrid() {
        WindLetter parsed = parser.parse(toJson(validOuter("obfuscation", "X25519ML-KEM-768", "wind+inner")));
        assertEquals("obfuscation", parsed.protectedHeader().windMode());
        assertEquals("X25519ML-KEM-768", parsed.protectedHeader().keyAlg());
        assertInstanceOf(Epk.class, parsed.protectedHeader().senderInfo());
        RecipientEntry recipient = parsed.recipients().get(0);
        ObfuscationRecipient obfuscationRecipient = assertInstanceOf(ObfuscationRecipient.class, recipient);
        assertEquals(1088, obfuscationRecipient.ek().length);
    }

    @Test
    void rejectsMalformedOuterJson() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("{"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsDuplicateOuterMemberAsMalformed() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        String wire = toJson(outer);
        String duplicate = "{\"aad\":\"" + outer.get("aad").asText() + "\"," + wire.substring(1);

        assertMalformed(duplicate);
    }

    @Test
    void rejectsDuplicateProtectedMemberAsMalformed() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode header = decodeProtected(outer.get("protected").asText());
        String headerJson = toJson(header);
        String duplicate = "{\"typ\":\"wind+jwe\"," + headerJson.substring(1);
        outer.put("protected", b64(duplicate.getBytes(StandardCharsets.UTF_8)));

        assertMalformed(toJson(outer));
    }

    @Test
    void rejectsDuplicateRecipientMemberAsMalformed() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        String recipientJson = toJson(recipient);
        String duplicateRecipient = "{\"encrypted_key\":\""
                + recipient.get("encrypted_key").asText() + "\"," + recipientJson.substring(1);

        assertMalformed(withRawRecipients(outer, "[" + duplicateRecipient + "]"));
    }

    @Test
    void rejectsDuplicateNestedKidMemberAsMalformed() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        ObjectNode kid = (ObjectNode) recipient.get("kid");
        String kidJson = toJson(kid);
        String duplicateKid = "{\"x25519\":\"" + kid.get("x25519").asText()
                + "\"," + kidJson.substring(1);
        String rawRecipient = "{\"kid\":" + duplicateKid + ",\"encrypted_key\":\""
                + recipient.get("encrypted_key").asText() + "\"}";

        assertMalformed(withRawRecipients(outer, "[" + rawRecipient + "]"));
    }

    @Test
    void rejectsTrailingSecondJsonTokenAsMalformed() {
        assertMalformed(toJson(validOuter("public", "X25519", "wind+jws")) + " {}");
    }

    @Test
    void rejectsBlankWireJsonAsMalformed() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("   "));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsNullTopLevelFieldsAsMalformed() {
        for (String field : new String[]{"protected", "aad", "recipients", "iv", "ciphertext", "tag"}) {
            ObjectNode outer = validOuter("public", "X25519", "wind+jws");
            outer.putNull(field);
            assertMalformed(toJson(outer));
        }
    }

    @Test
    void rejectsWrongTypeTopLevelFieldsAsMalformed() {
        for (String field : new String[]{"protected", "aad", "iv", "ciphertext", "tag"}) {
            ObjectNode outer = validOuter("public", "X25519", "wind+jws");
            outer.putObject(field).put("wrong", true);
            assertMalformed(toJson(outer));
        }
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("recipients", "wrong");
        assertMalformed(toJson(outer));
    }

    @Test
    void rejectsNullProtectedFieldsAsMalformed() {
        for (String field : new String[]{"typ", "cty", "ver", "wind_mode", "enc", "key_alg", "kid"}) {
            ObjectNode outer = validOuter("public", "X25519", "wind+jws");
            ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
            protectedHeader.putNull(field);
            outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
            assertMalformed(toJson(outer));
        }
    }

    @Test
    void rejectsWrongTypeProtectedFieldsAsMalformed() {
        for (String field : new String[]{"typ", "cty", "ver", "wind_mode", "enc", "key_alg"}) {
            ObjectNode outer = validOuter("public", "X25519", "wind+jws");
            ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
            protectedHeader.putObject(field).put("wrong", true);
            outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
            assertMalformed(toJson(outer));
        }
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("kid", "wrong");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        assertMalformed(toJson(outer));
    }

    @Test
    void rejectsNullRecipientAndNestedKidFieldsAsMalformed() {
        ObjectNode nullRecipientKid = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) nullRecipientKid.withArray("recipients").get(0)).putNull("kid");
        assertMalformed(toJson(nullRecipientKid));

        ObjectNode nullEncryptedKey = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) nullEncryptedKey.withArray("recipients").get(0)).putNull("encrypted_key");
        assertMalformed(toJson(nullEncryptedKey));

        ObjectNode nullNestedKid = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) nullNestedKid.withArray("recipients").get(0).get("kid")).putNull("x25519");
        assertMalformed(toJson(nullNestedKid));
    }

    @Test
    void rejectsWrongTypeRecipientAndNestedKidFieldsAsMalformed() {
        ObjectNode wrongRecipientKid = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) wrongRecipientKid.withArray("recipients").get(0)).put("kid", "wrong");
        assertMalformed(toJson(wrongRecipientKid));

        ObjectNode wrongEncryptedKey = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) wrongEncryptedKey.withArray("recipients").get(0))
                .putObject("encrypted_key").put("wrong", true);
        assertMalformed(toJson(wrongEncryptedKey));

        ObjectNode wrongNestedKid = validOuter("public", "X25519", "wind+jws");
        ((ObjectNode) wrongNestedKid.withArray("recipients").get(0).get("kid"))
                .putObject("x25519").put("wrong", true);
        assertMalformed(toJson(wrongNestedKid));
    }

    @Test
    void acceptsPublicRecipientCountBoundaries() {
        for (int count : new int[]{1, 2, 32}) {
            WindLetter parsed = parser.parse(toJson(outerWithRecipientCount("public", "X25519", count)));
            assertEquals(count, parsed.recipients().size());
        }
    }

    @Test
    void rejectsPublicRecipientCountOutsideBounds() {
        for (int count : new int[]{0, 33}) {
            ProtocolException ex = assertThrows(
                    ProtocolException.class,
                    () -> parser.parse(toJson(outerWithRecipientCount("public", "X25519", count)))
            );
            assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
        }
    }

    @Test
    void acceptsObfuscationRecipientBuckets() {
        for (int count : new int[]{8, 16, 32}) {
            WindLetter parsed = parser.parse(toJson(outerWithRecipientCount("obfuscation", "X25519", count)));
            assertEquals(count, parsed.recipients().size());
        }
    }

    @Test
    void rejectsObfuscationRecipientCountsOutsideBuckets() {
        for (int count : new int[]{1, 7, 9, 15, 17, 31, 33}) {
            ProtocolException ex = assertThrows(
                    ProtocolException.class,
                    () -> parser.parse(toJson(outerWithRecipientCount("obfuscation", "X25519", count)))
            );
            assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
        }
    }

    @Test
    void rejectsJsonDepthThirtyThreeAsMalformed() {
        String nested = "0";
        for (int i = 0; i < 33; i++) {
            nested = "{\"nested\":" + nested + "}";
        }

        assertMalformed(nested);
    }

    @Test
    void rejectsWireWhoseUtf8EncodingExceedsTwentyMebibytes() {
        int repeatedCharacters = (20 * 1024 * 1024) / 2 + 1;
        String wire = "{\"unknown\":\"" + "é".repeat(repeatedCharacters) + "\"}";

        assertMalformed(wire);
    }

    @Test
    void rejectsUnpairedUtf16SurrogatesAsMalformed() {
        for (String surrogate : new String[]{"\uD800", "\uDC00"}) {
            String validOuter = toJson(validOuter("public", "X25519", "wind+jws"));
            String wire = "{\"unknown\":\"" + surrogate + "\"," + validOuter.substring(1);

            assertMalformed(wire);
        }
    }

    @Test
    void acceptsValidSurrogatePairDuringUtf8LengthCheck() {
        String validOuter = toJson(validOuter("public", "X25519", "wind+jws"));
        String wire = "{\"unknown\":\"\uD83D\uDE00\"," + validOuter.substring(1);

        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsDecodedCiphertextLargerThanTwelveMebibytes() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("ciphertext", b64(bytes(12 * 1024 * 1024 + 1, 42)));

        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsUnsupportedVersion() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("ver", "2.0");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.UNSUPPORTED_VERSION, ex.errorCode());
    }

    @Test
    void rejectsUnsupportedEncAlgorithm() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("enc", "A128GCM");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void rejectsUnsupportedKeyAlgorithm() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("key_alg", "RSA-OAEP");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void malformedBeatsUnsupportedVersionAndUnknownField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("ver", "2.0");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        outer.put("aad", "bad==");
        outer.put("unknown", "x");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void unsupportedVersionBeatsUnsupportedAlgorithmAndInvalidField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("ver", "2.0");
        protectedHeader.put("enc", "A128GCM");
        protectedHeader.put("typ", "bad-typ");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.UNSUPPORTED_VERSION, ex.errorCode());
    }

    @Test
    void malformedProtectedShapeBeatsUnsupportedVersion() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("ver", "2.0");
        protectedHeader.putObject("typ").put("bad", "shape");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void unsupportedAlgorithmBeatsInvalidField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.put("enc", "A128GCM");
        protectedHeader.put("typ", "bad-typ");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void malformedBeatsUnknownRecipientFieldInBranch() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("encrypted_key", "bad==");
        recipient.put("unknown", "x");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsInvalidProtectedBase64() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("protected", "bad==");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsProtectedDecodedNotJson() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("protected", b64("not-json".getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsInvalidAadUnpaddedBase64Url() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("aad", "bad==");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void malformedAadBeatsMissingProtected() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.remove("protected");
        outer.put("aad", "bad==");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void malformedIvBeatsBlankProtected() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("protected", "");
        outer.put("iv", "bad==");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void rejectsInvalidIvLength() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("iv", b64(bytes(11, 1)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidTagLength() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("tag", b64(bytes(15, 2)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidRidLength() {
        ObjectNode outer = validOuter("obfuscation", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("rid", b64(bytes(15, 3)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidEpkXLength() {
        ObjectNode outer = validOuter("obfuscation", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        ((ObjectNode) protectedHeader.get("epk")).put("x", b64(bytes(31, 4)));
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidProtectedKidX25519Length() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        ((ObjectNode) protectedHeader.get("kid")).put("x25519", b64(bytes(31, 5)));
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidRecipientKidMlkem768Length() {
        ObjectNode outer = validOuter("public", "X25519ML-KEM-768", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        ObjectNode kid = (ObjectNode) recipient.get("kid");
        kid.put("mlkem768", b64(bytes(31, 6)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidEkLength() {
        ObjectNode outer = validOuter("public", "X25519ML-KEM-768", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("ek", b64(bytes(1087, 7)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsInvalidEncryptedKeyLength() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("encrypted_key", b64(bytes(39, 8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsPublicWithEpk() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.set("epk", MAPPER.createObjectNode()
                .put("kty", "OKP")
                .put("crv", "X25519")
                .put("x", b64(bytes(32, 9))));
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsObfuscationWithKid() {
        ObjectNode outer = validOuter("obfuscation", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        protectedHeader.set("kid", MAPPER.createObjectNode().put("x25519", b64(bytes(32, 10))));
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsX25519WithEk() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("ek", b64(bytes(1088, 11)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsHybridMissingEk() {
        ObjectNode outer = validOuter("obfuscation", "X25519ML-KEM-768", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.remove("ek");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsUnknownField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        outer.put("unknown", "x");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsUnknownProtectedKidField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        ObjectNode kid = (ObjectNode) protectedHeader.get("kid");
        kid.put("unknown", "x");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsUnknownProtectedEpkField() {
        ObjectNode outer = validOuter("obfuscation", "X25519", "wind+jws");
        ObjectNode protectedHeader = decodeProtected(outer.get("protected").asText());
        ObjectNode epk = (ObjectNode) protectedHeader.get("epk");
        epk.put("unknown", "x");
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void rejectsUnknownRecipientKidField() {
        ObjectNode outer = validOuter("public", "X25519", "wind+jws");
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        ObjectNode kid = (ObjectNode) recipient.get("kid");
        kid.put("unknown", "x");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    private static ObjectNode validOuter(String windMode, String keyAlg, String cty) {
        ObjectNode protectedHeader = MAPPER.createObjectNode()
                .put("typ", "wind+jwe")
                .put("cty", cty)
                .put("ver", "1.0")
                .put("wind_mode", windMode)
                .put("enc", "A256GCM")
                .put("key_alg", keyAlg);
        if ("public".equals(windMode)) {
            protectedHeader.set("kid", MAPPER.createObjectNode().put("x25519", b64(bytes(32, 20))));
        } else {
            protectedHeader.set("epk", MAPPER.createObjectNode()
                    .put("kty", "OKP")
                    .put("crv", "X25519")
                    .put("x", b64(bytes(32, 21))));
        }

        ObjectNode outer = MAPPER.createObjectNode();
        outer.put("protected", b64(toJson(protectedHeader).getBytes(StandardCharsets.UTF_8)));
        outer.put("aad", b64("{\"r\":1}".getBytes(StandardCharsets.UTF_8)));
        outer.put("iv", b64(bytes(12, 22)));
        outer.put("ciphertext", b64(bytes(24, 23)));
        outer.put("tag", b64(bytes(16, 24)));
        ArrayNode recipients = MAPPER.createArrayNode();
        int recipientCount = "obfuscation".equals(windMode) ? 8 : 1;
        for (int i = 0; i < recipientCount; i++) {
            recipients.add(validRecipient(windMode, keyAlg));
        }
        outer.set("recipients", recipients);
        return outer;
    }

    private static ObjectNode outerWithRecipientCount(String windMode, String keyAlg, int count) {
        ObjectNode outer = validOuter(windMode, keyAlg, "wind+jws");
        ArrayNode recipients = MAPPER.createArrayNode();
        for (int i = 0; i < count; i++) {
            recipients.add(validRecipient(windMode, keyAlg));
        }
        outer.set("recipients", recipients);
        return outer;
    }

    private static ObjectNode validRecipient(String windMode, String keyAlg) {
        ObjectNode recipient = MAPPER.createObjectNode();
        if ("public".equals(windMode)) {
            ObjectNode kid = MAPPER.createObjectNode().put("x25519", b64(bytes(32, 30)));
            if ("X25519ML-KEM-768".equals(keyAlg)) {
                kid.put("mlkem768", b64(bytes(32, 31)));
            }
            recipient.set("kid", kid);
        } else {
            recipient.put("rid", b64(bytes(16, 32)));
        }
        if ("X25519ML-KEM-768".equals(keyAlg)) {
            recipient.put("ek", b64(bytes(1088, 33)));
        }
        recipient.put("encrypted_key", b64(bytes(40, 34)));
        return recipient;
    }

    private static ObjectNode decodeProtected(String protectedValue) {
        byte[] decoded = Base64.getUrlDecoder().decode(protectedValue);
        try {
            return (ObjectNode) MAPPER.readTree(decoded);
        } catch (IOException e) {
            throw new IllegalStateException("failed to parse protected header in test setup", e);
        }
    }

    private static byte[] bytes(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((seed + i) & 0xff);
        }
        return out;
    }

    private static String b64(byte[] value) {
        return BASE64_URL.encodeToString(value);
    }

    private static String withRawRecipients(ObjectNode outer, String rawRecipients) {
        String wire = toJson(outer);
        String serializedRecipients = toJson(outer.get("recipients"));
        return wire.replace("\"recipients\":" + serializedRecipients, "\"recipients\":" + rawRecipients);
    }

    private void assertMalformed(String wire) {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wire));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    private static String toJson(com.fasterxml.jackson.databind.JsonNode node) {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to build test json", e);
        }
    }
}
