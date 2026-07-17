package com.windletter.protocol.inner;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.ProtocolLimits;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UnsignedInnerCodecTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final String HASH_11 = "ERERERERERERERERERERERERERERERERERERERERERE";
    private static final String HASH_22 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
    private static final String PROTECTED = "{"
            + "\"jwe_protected_hash\":\"" + HASH_11 + "\","
            + "\"jwe_recipients_hash\":\"" + HASH_22 + "\","
            + "\"ts\":" + TIMESTAMP + ","
            + "\"typ\":\"wind+inner\","
            + "\"wind_id\":\"" + MESSAGE_ID + "\"}"
            ;
    private static final String META = "{\"content_type\":\"application/octet-stream\",\"original_size\":3}";
    private static final String BODY = "{\"data\":\"AAEC\"}";
    private static final String PAYLOAD = "{\"body\":" + BODY + ",\"meta\":" + META + "}";
    private static final String VALID_JSON = "{\"payload\":" + PAYLOAD + ",\"protected\":" + PROTECTED + "}";
    private static final String EXACT_JCS_VECTOR = "{\"payload\":{\"body\":{\"data\":\"AAEC\"},"
            + "\"meta\":{\"content_type\":\"application/octet-stream\",\"original_size\":3}},"
            + "\"protected\":{\"jwe_protected_hash\":\"ERERERERERERERERERERERERERERERERERERERERERE\","
            + "\"jwe_recipients_hash\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI\","
            + "\"ts\":1731800000,\"typ\":\"wind+inner\","
            + "\"wind_id\":\"123e4567-e89b-42d3-a456-426614174000\"}}";

    private final UnsignedInnerCodec codec = new UnsignedInnerCodec();

    @Test
    void encodesTheAuditedJcsVectorAndRoundTripsArbitraryBinary() {
        byte[] data = {0, 1, 2};
        byte[] protectedHash = filled(32, 0x11);
        byte[] recipientsHash = filled(32, 0x22);
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", data, data.length);
        OuterBinding.Hashes binding = new OuterBinding.Hashes(protectedHash, recipientsHash);
        UnsignedInnerCodec.Message message = new UnsignedInnerCodec.Message(
                MESSAGE_ID, TIMESTAMP, payload, binding
        );

        byte[] encoded = codec.encode(message);
        UnsignedInnerCodec.Message decoded = codec.decode(encoded);

        assertEquals(EXACT_JCS_VECTOR, new String(encoded, StandardCharsets.UTF_8));
        assertEquals(MESSAGE_ID, decoded.messageId());
        assertEquals(TIMESTAMP, decoded.timestamp());
        assertEquals("application/octet-stream", decoded.payload().contentType());
        assertEquals(3, decoded.payload().originalSize());
        assertArrayEquals(data, decoded.payload().data());
        assertArrayEquals(protectedHash, decoded.binding().protectedHash());
        assertArrayEquals(recipientsHash, decoded.binding().recipientsHash());
    }

    @Test
    void acceptsAnEmptyPayloadAndCanonicalEmptyBase64Url() {
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", new byte[0], 0);
        UnsignedInnerCodec.Message decoded = codec.decode(codec.encode(new UnsignedInnerCodec.Message(
                MESSAGE_ID,
                0,
                payload,
                new OuterBinding.Hashes(filled(32, 0x11), filled(32, 0x22))
        )));

        assertEquals(0, decoded.payload().originalSize());
        assertArrayEquals(new byte[0], decoded.payload().data());
        assertEquals("", readDataValue(codec.encode(decoded)));
    }

    @Test
    void protocolPayloadDefensivelyCopiesDataAndRequiresMatchingBoundedSize() {
        byte[] source = {0, (byte) 0xff, 2};
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", source, 3);
        source[0] = 9;

        byte[] firstRead = payload.data();
        assertArrayEquals(new byte[]{0, (byte) 0xff, 2}, firstRead);
        assertNotSame(source, firstRead);
        firstRead[1] = 0;
        assertArrayEquals(new byte[]{0, (byte) 0xff, 2}, payload.data());

        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload(null, new byte[0], 0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload(" ", new byte[0], 0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload("application/octet-stream", new byte[0], -1));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload("application/octet-stream", new byte[0], 1));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload("application/octet-stream", new byte[0],
                        ProtocolLimits.MAX_PAYLOAD_BYTES + 1L));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolPayload("application/octet-stream", null, 0));
        assertArrayEquals(new ProtocolAuthenticationStatus[]{
                        ProtocolAuthenticationStatus.UNSIGNED,
                        ProtocolAuthenticationStatus.SIGNED_VALID
                },
                ProtocolAuthenticationStatus.values());
    }

    @Test
    void messageRejectsInvalidTrustedInputs() {
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", new byte[0], 0);
        OuterBinding.Hashes binding = new OuterBinding.Hashes(new byte[32], new byte[32]);

        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message(null, 0, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message("123E4567-E89B-42D3-A456-426614174000", 0, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message("123e4567-e89b-12d3-a456-426614174000", 0, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message("123e4567-e89b-42d3-7456-426614174000", 0, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message(MESSAGE_ID, -1, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message(MESSAGE_ID, 9_007_199_254_740_992L, payload, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message(MESSAGE_ID, 0, null, binding));
        assertThrows(IllegalArgumentException.class,
                () -> new UnsignedInnerCodec.Message(MESSAGE_ID, 0, payload, null));
    }

    @TestFactory
    Stream<DynamicTest> rejectsDuplicatesAtEveryObjectLayerAsMalformed() {
        return malformedCases(List.of(
                named("root", "{\"payload\":" + PAYLOAD + ",\"payload\":" + PAYLOAD
                        + ",\"protected\":" + PROTECTED + "}"),
                named("protected", VALID_JSON.replace("\"typ\":\"wind+inner\",",
                        "\"typ\":\"wind+inner\",\"typ\":\"wind+inner\",")),
                named("payload", VALID_JSON.replace("\"body\":" + BODY + ",",
                        "\"body\":" + BODY + ",\"body\":" + BODY + ",")),
                named("meta", VALID_JSON.replace("\"content_type\":\"application/octet-stream\",",
                        "\"content_type\":\"application/octet-stream\","
                                + "\"content_type\":\"application/octet-stream\",")),
                named("body", VALID_JSON.replace("\"data\":\"AAEC\"",
                        "\"data\":\"AAEC\",\"data\":\"AAEC\""))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsUnknownFieldsAtEveryObjectLayerAsInvalidField() {
        return invalidCases(List.of(
                named("root", VALID_JSON.substring(0, VALID_JSON.length() - 1) + ",\"extra\":0}"),
                named("protected", VALID_JSON.replace("\"wind_id\":\"" + MESSAGE_ID + "\"}",
                        "\"wind_id\":\"" + MESSAGE_ID + "\",\"extra\":0}")),
                named("payload", VALID_JSON.replace("\"meta\":" + META + "}",
                        "\"meta\":" + META + ",\"extra\":0}")),
                named("meta", VALID_JSON.replace("\"original_size\":3}",
                        "\"original_size\":3,\"extra\":0}")),
                named("body", VALID_JSON.replace("\"data\":\"AAEC\"}",
                        "\"data\":\"AAEC\",\"extra\":0}"))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsNullsAtEveryObjectLayerAsMalformed() {
        return malformedCases(List.of(
                named("root", "null"),
                named("protected", VALID_JSON.replace(PROTECTED, "null")),
                named("payload", VALID_JSON.replace(PAYLOAD, "null")),
                named("meta", VALID_JSON.replace(META, "null")),
                named("body", VALID_JSON.replace(BODY, "null")),
                named("protected field", VALID_JSON.replace("\"typ\":\"wind+inner\"", "\"typ\":null")),
                named("meta field", VALID_JSON.replace("\"content_type\":\"application/octet-stream\"",
                        "\"content_type\":null")),
                named("body field", VALID_JSON.replace("\"data\":\"AAEC\"", "\"data\":null"))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsWrongTypesAtEveryObjectLayerAsMalformed() {
        return malformedCases(List.of(
                named("root", "[]"),
                named("protected", VALID_JSON.replace(PROTECTED, "\"flattened\"")),
                named("payload", VALID_JSON.replace(PAYLOAD, "\"flattened\"")),
                named("meta", VALID_JSON.replace(META, "[]")),
                named("body", VALID_JSON.replace(BODY, "0")),
                named("protected field", VALID_JSON.replace("\"ts\":" + TIMESTAMP, "\"ts\":\"1\"")),
                named("meta field", VALID_JSON.replace("\"original_size\":3", "\"original_size\":\"3\"")),
                named("body field", VALID_JSON.replace("\"data\":\"AAEC\"", "\"data\":3"))
        ));
    }

    @Test
    void rejectsTrailingJsonAndInvalidUtf8AsMalformed() {
        assertError(ErrorCode.MALFORMED_WIRE, (VALID_JSON + " true").getBytes(StandardCharsets.UTF_8));
        assertError(ErrorCode.MALFORMED_WIRE,
                new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '(', '"', '}'});
    }

    @TestFactory
    Stream<DynamicTest> rejectsMissingAndUnsignedDisallowedFieldsAsInvalidField() {
        return invalidCases(List.of(
                named("missing root field", "{\"protected\":" + PROTECTED + "}"),
                named("missing protected field", VALID_JSON.replace("\"typ\":\"wind+inner\",", "")),
                named("missing payload field", VALID_JSON.replace("\"body\":" + BODY + ",", "")),
                named("missing meta field", VALID_JSON.replace("\"content_type\":\"application/octet-stream\",", "")),
                named("missing body field", VALID_JSON.replace("\"data\":\"AAEC\"", "")),
                named("root signature", VALID_JSON.substring(0, VALID_JSON.length() - 1)
                        + ",\"signature\":\"AA\"}"),
                named("protected alg", VALID_JSON.replace("\"typ\":\"wind+inner\",",
                        "\"alg\":\"EdDSA\",\"typ\":\"wind+inner\",")),
                named("protected kid", VALID_JSON.replace("\"typ\":\"wind+inner\",",
                        "\"kid\":\"AA\",\"typ\":\"wind+inner\",")),
                named("debug ciphertext wrapper", "{\"ciphertext\":" + VALID_JSON + "}")
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsNonCanonicalBase64UrlAndWrongHashLengths() {
        String hash31 = b64(new byte[31]);
        String hash33 = b64(new byte[33]);
        return Stream.of(
                dynamicInvalid("padded payload", VALID_JSON.replace("\"AAEC\"", "\"AAEC=\""),
                        ErrorCode.MALFORMED_WIRE),
                dynamicInvalid("non-canonical payload", VALID_JSON.replace("\"AAEC\"", "\"AB\""),
                        ErrorCode.MALFORMED_WIRE),
                dynamicInvalid("non-URL payload alphabet", VALID_JSON.replace("\"AAEC\"", "\"AA+C\""),
                        ErrorCode.MALFORMED_WIRE),
                dynamicInvalid("padded hash", VALID_JSON.replace(HASH_11, HASH_11 + "="),
                        ErrorCode.MALFORMED_WIRE),
                dynamicInvalid("non-URL hash alphabet", VALID_JSON.replace(HASH_11, HASH_11.substring(0, 42) + "+"),
                        ErrorCode.MALFORMED_WIRE),
                dynamicInvalid("31 byte protected hash", VALID_JSON.replace(HASH_11, hash31),
                        ErrorCode.INVALID_FIELD),
                dynamicInvalid("33 byte protected hash", VALID_JSON.replace(HASH_11, hash33),
                        ErrorCode.INVALID_FIELD),
                dynamicInvalid("31 byte recipients hash", VALID_JSON.replace(HASH_22, hash31),
                        ErrorCode.INVALID_FIELD),
                dynamicInvalid("33 byte recipients hash", VALID_JSON.replace(HASH_22, hash33),
                        ErrorCode.INVALID_FIELD)
        );
    }

    @TestFactory
    Stream<DynamicTest> rejectsNonCanonicalOrNonV4MessageIds() {
        return invalidCases(List.of(
                named("shortened", withMessageId("123e4567-e89b-42d3-a456-42661417400")),
                named("uppercase", withMessageId("123E4567-E89B-42D3-A456-426614174000")),
                named("version 1", withMessageId("123e4567-e89b-12d3-a456-426614174000")),
                named("wrong variant", withMessageId("123e4567-e89b-42d3-7456-426614174000"))
        ));
    }

    @TestFactory
    Stream<DynamicTest>rejectsInvalidTimestampRepresentationsAndBounds() {
        return invalidCases(List.of(
                named("negative", withTimestamp("-1")),
                named("above safe integer", withTimestamp("9007199254740992")),
                named("decimal", withTimestamp("1.0")),
                named("exponent", withTimestamp("1e0"))
        ));
    }

    @Test
    void rejectsOriginalSizeMismatchAndOverflow() {
        assertInvalid(VALID_JSON.replace("\"original_size\":3", "\"original_size\":-1"));
        assertInvalid(VALID_JSON.replace("\"original_size\":3", "\"original_size\":4"));
        assertInvalid(VALID_JSON.replace("\"original_size\":3", "\"original_size\":8388609"));
        assertInvalid(VALID_JSON.replace("\"original_size\":3", "\"original_size\":1.0"));
    }

    @Test
    void rejectsPayloadAndInnerInputsAboveStageLimits() {
        byte[] oversizedPayload = new byte[ProtocolLimits.MAX_PAYLOAD_BYTES + 1];
        String oversizedJson = VALID_JSON
                .replace("\"AAEC\"", "\"" + b64(oversizedPayload) + "\"")
                .replace("\"original_size\":3", "\"original_size\":" + oversizedPayload.length);

        assertError(ErrorCode.INVALID_FIELD, oversizedJson.getBytes(StandardCharsets.UTF_8));
        assertError(ErrorCode.INVALID_FIELD, new byte[ProtocolLimits.MAX_INNER_BYTES + 1]);
    }

    @Test
    void rejectsInvalidProtectedAndMetadataValues() {
        assertInvalid(VALID_JSON.replace("\"typ\":\"wind+inner\"", "\"typ\":\"wind+jws\""));
        assertInvalid(VALID_JSON.replace("\"content_type\":\"application/octet-stream\"",
                "\"content_type\":\" \""));
    }

    private Stream<DynamicTest> malformedCases(List<NamedJson> cases) {
        return cases.stream().map(value -> DynamicTest.dynamicTest(value.name(),
                () -> assertMalformed(value.json())));
    }

    private Stream<DynamicTest> invalidCases(List<NamedJson> cases) {
        return cases.stream().map(value -> DynamicTest.dynamicTest(value.name(),
                () -> assertInvalid(value.json())));
    }

    private DynamicTest dynamicInvalid(String name, String json, ErrorCode expected) {
        return DynamicTest.dynamicTest(name,
                () -> assertError(expected, json.getBytes(StandardCharsets.UTF_8)));
    }

    private void assertMalformed(String json) {
        assertError(ErrorCode.MALFORMED_WIRE, json.getBytes(StandardCharsets.UTF_8));
    }

    private void assertInvalid(String json) {
        assertError(ErrorCode.INVALID_FIELD, json.getBytes(StandardCharsets.UTF_8));
    }

    private void assertError(ErrorCode expected, byte[] bytes) {
        ProtocolException failure = assertThrows(ProtocolException.class, () -> codec.decode(bytes));
        assertEquals(expected, failure.errorCode());
    }

    private static NamedJson named(String name, String json) {
        return new NamedJson(name, json);
    }

    private static String withMessageId(String messageId) {
        return VALID_JSON.replace(MESSAGE_ID, messageId);
    }

    private static String withTimestamp(String timestamp) {
        return VALID_JSON.replace("\"ts\":" + TIMESTAMP, "\"ts\":" + timestamp);
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static String readDataValue(byte[] encoded) {
        String json = new String(encoded, StandardCharsets.UTF_8);
        int marker = json.indexOf("\"data\":\"") + "\"data\":\"".length();
        return json.substring(marker, json.indexOf('"', marker));
    }

    private record NamedJson(String name, String json) {
    }
}
