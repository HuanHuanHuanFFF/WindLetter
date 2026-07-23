package com.windletter.protocol.flow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.parser.OuterWireParser;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ObfuscationHybridOuterWireStrictTest {

    private static final String BASE64_URL_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final OuterWireParser PARSER = new JacksonOuterWireParser();

    private static String realSenderWire;

    @BeforeAll
    static void createRealSenderWire() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            realSenderWire = fixture.send(fixture.binaryPayload());
        }
    }

    @Test
    void enforcesRequiredAndForbiddenHybridObfuscationFields() {
        ObjectNode missingEpk = realOuter();
        ObjectNode missingEpkHeader = protectedHeader(missingEpk);
        missingEpkHeader.remove("epk");
        replaceProtected(missingEpk, missingEpkHeader);
        assertCode(ErrorCode.INVALID_FIELD, missingEpk);

        ObjectNode forbiddenHeaderKid = realOuter();
        ObjectNode forbiddenHeaderKidValue = protectedHeader(forbiddenHeaderKid);
        forbiddenHeaderKidValue.set(
                "kid",
                JSON.createObjectNode().put("x25519", Base64Url.encode(bytes(32, 1)))
        );
        replaceProtected(forbiddenHeaderKid, forbiddenHeaderKidValue);
        assertCode(ErrorCode.INVALID_FIELD, forbiddenHeaderKid);

        for (String required : List.of("rid", "ek", "encrypted_key")) {
            ObjectNode missingRecipientField = realOuter();
            firstRecipient(missingRecipientField).remove(required);
            assertCode(ErrorCode.INVALID_FIELD, missingRecipientField);
        }

        ObjectNode forbiddenRecipientKid = realOuter();
        firstRecipient(forbiddenRecipientKid).set(
                "kid",
                JSON.createObjectNode()
                        .put("x25519", Base64Url.encode(bytes(32, 2)))
                        .put("mlkem768", Base64Url.encode(bytes(32, 3)))
        );
        assertCode(ErrorCode.INVALID_FIELD, forbiddenRecipientKid);
    }

    @Test
    void rejectsHybridEkLengthsOtherThan1088Bytes() {
        for (int length : new int[]{1087, 1089}) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put("ek", Base64Url.encode(bytes(length, length)));

            assertCode(ErrorCode.INVALID_FIELD, outer);
        }
    }

    @Test
    void rejectsCommonFixedLengthsOnTheActualHybridProfile() {
        for (int length : new int[]{15, 17}) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put(
                    "rid", Base64Url.encode(bytes(length, length))
            );
            assertCode(ErrorCode.INVALID_FIELD, outer);
        }

        for (int length : new int[]{39, 41}) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put(
                    "encrypted_key", Base64Url.encode(bytes(length, length))
            );
            assertCode(ErrorCode.INVALID_FIELD, outer);
        }

        for (int length : new int[]{31, 33}) {
            ObjectNode outer = realOuter();
            ObjectNode header = protectedHeader(outer);
            ((ObjectNode) header.get("epk")).put(
                    "x", Base64Url.encode(bytes(length, length))
            );
            replaceProtected(outer, header);
            assertCode(ErrorCode.INVALID_FIELD, outer);
        }
    }

    @Test
    void rejectsPaddedIllegalAlphabetAndNonCanonicalTrailingBitsInHybridEk() {
        for (String malformed : malformedCanonicalVariants(bytes(1088, 41))) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put("ek", malformed);

            assertCode(ErrorCode.MALFORMED_WIRE, outer);
        }
    }

    @Test
    void rejectsNonCanonicalCommonEncodingsOnTheActualHybridProfile() {
        for (String malformed : malformedCanonicalVariants(bytes(16, 42))) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put("rid", malformed);
            assertCode(ErrorCode.MALFORMED_WIRE, outer);
        }

        for (String malformed : malformedCanonicalVariants(bytes(40, 43))) {
            ObjectNode outer = realOuter();
            firstRecipient(outer).put("encrypted_key", malformed);
            assertCode(ErrorCode.MALFORMED_WIRE, outer);
        }

        for (String malformed : malformedCanonicalVariants(bytes(32, 44))) {
            ObjectNode outer = realOuter();
            ObjectNode header = protectedHeader(outer);
            ((ObjectNode) header.get("epk")).put("x", malformed);
            replaceProtected(outer, header);
            assertCode(ErrorCode.MALFORMED_WIRE, outer);
        }
    }

    @Test
    void rejectsEveryNonBucketRecipientCountAtHybridObfuscationBoundaries() {
        for (int count : new int[]{7, 9, 15, 17, 31, 33}) {
            ObjectNode outer = realOuter();
            ArrayNode original = outer.withArray("recipients");
            List<JsonNode> templates = new ArrayList<>(original.size());
            original.forEach(value -> templates.add(value.deepCopy()));
            ArrayNode resized = JSON.createArrayNode();
            for (int i = 0; i < count; i++) {
                resized.add(templates.get(i % templates.size()).deepCopy());
            }
            outer.set("recipients", resized);

            assertCode(ErrorCode.INVALID_FIELD, outer);
        }
    }

    @Test
    void eightEntryHybridWriterRoundTripPreservesRecipientOrderAndAllThreeFields() {
        WindLetter first = PARSER.parse(realSenderWire);
        String rewritten = new JacksonOuterWireWriter().write(first);
        ObjectNode rewrittenJson = parseObject(rewritten);
        WindLetter second = PARSER.parse(rewritten);

        assertEquals(8, first.recipients().size());
        assertEquals(8, second.recipients().size());
        ArrayNode rawRecipients = rewrittenJson.withArray("recipients");
        assertEquals(8, rawRecipients.size());
        for (int i = 0; i < 8; i++) {
            ObjectNode rawRecipient = assertInstanceOf(
                    ObjectNode.class, rawRecipients.get(i)
            );
            assertEquals(
                    Set.of("rid", "ek", "encrypted_key"),
                    fieldNames(rawRecipient)
            );

            ObfuscationRecipient expected = assertInstanceOf(
                    ObfuscationRecipient.class, first.recipients().get(i)
            );
            ObfuscationRecipient actual = assertInstanceOf(
                    ObfuscationRecipient.class, second.recipients().get(i)
            );
            byte[] expectedRid = expected.rid();
            byte[] actualRid = actual.rid();
            byte[] expectedEk = expected.ek();
            byte[] actualEk = actual.ek();
            byte[] expectedEncryptedKey = expected.encryptedKey();
            byte[] actualEncryptedKey = actual.encryptedKey();
            try {
                assertArrayEquals(expectedRid, actualRid);
                assertArrayEquals(expectedEk, actualEk);
                assertArrayEquals(expectedEncryptedKey, actualEncryptedKey);
            } finally {
                Arrays.fill(expectedRid, (byte) 0);
                Arrays.fill(actualRid, (byte) 0);
                Arrays.fill(expectedEk, (byte) 0);
                Arrays.fill(actualEk, (byte) 0);
                Arrays.fill(expectedEncryptedKey, (byte) 0);
                Arrays.fill(actualEncryptedKey, (byte) 0);
            }
        }
    }

    private static ObjectNode realOuter() {
        return parseObject(realSenderWire);
    }

    private static ObjectNode protectedHeader(ObjectNode outer) {
        byte[] encoded = Base64Url.decodeCanonical(
                outer.get("protected").textValue(), "test.protected"
        );
        try {
            return parseObject(new String(encoded, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void replaceProtected(ObjectNode outer, ObjectNode header) {
        try {
            outer.put("protected", Base64Url.encode(JSON.writeValueAsBytes(header)));
        } catch (JsonProcessingException e) {
            throw new AssertionError("failed to encode protected test header", e);
        }
    }

    private static ObjectNode firstRecipient(ObjectNode outer) {
        return (ObjectNode) outer.withArray("recipients").get(0);
    }

    private static void assertCode(ErrorCode expected, ObjectNode outer) {
        ProtocolException error = assertThrows(
                ProtocolException.class,
                () -> PARSER.parse(toJson(outer))
        );
        assertEquals(expected, error.errorCode());
    }

    private static String nonCanonicalAlias(String canonical) {
        int remainder = canonical.length() % 4;
        if (remainder != 2 && remainder != 3) {
            throw new AssertionError("fixture must contain unused trailing bits");
        }
        int lastIndex = canonical.length() - 1;
        int alphabetIndex = BASE64_URL_ALPHABET.indexOf(canonical.charAt(lastIndex));
        if (alphabetIndex < 0 || alphabetIndex == BASE64_URL_ALPHABET.length() - 1) {
            throw new AssertionError("fixture does not support a trailing-bit alias");
        }
        return canonical.substring(0, lastIndex)
                + BASE64_URL_ALPHABET.charAt(alphabetIndex + 1);
    }

    private static List<String> malformedCanonicalVariants(byte[] value) {
        String canonical = Base64Url.encode(value);
        return List.of(
                canonical + "=",
                "+" + canonical.substring(1),
                nonCanonicalAlias(canonical)
        );
    }

    private static Set<String> fieldNames(ObjectNode node) {
        HashSet<String> fields = new HashSet<>();
        node.fieldNames().forEachRemaining(fields::add);
        return fields;
    }

    private static byte[] bytes(int length, int seed) {
        byte[] value = new byte[length];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) ((seed + i) & 0xff);
        }
        return value;
    }

    private static ObjectNode parseObject(String json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (JsonProcessingException e) {
            throw new AssertionError("failed to parse test JSON", e);
        }
    }

    private static String toJson(JsonNode node) {
        try {
            return JSON.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new AssertionError("failed to serialize test JSON", e);
        }
    }
}
