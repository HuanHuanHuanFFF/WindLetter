package com.windletter.protocol.inner;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.ProtocolLimits;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignedInnerCodecTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final String SIGNING_KID = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
    private static final String HASH_11 = "ERERERERERERERERERERERERERERERERERERERERERE";
    private static final String HASH_22 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
    private static final String HEADER = "{"
            + "\"alg\":\"EdDSA\","
            + "\"jwe_protected_hash\":\"" + HASH_11 + "\","
            + "\"jwe_recipients_hash\":\"" + HASH_22 + "\","
            + "\"kid\":\"" + SIGNING_KID + "\","
            + "\"ts\":" + TIMESTAMP + ","
            + "\"typ\":\"wind+jws\","
            + "\"wind_id\":\"" + MESSAGE_ID + "\"}"
            ;
    private static final String META = "{\"content_type\":\"application/octet-stream\",\"original_size\":3}";
    private static final String BODY = "{\"data\":\"AAEC\"}";
    private static final String PAYLOAD = "{\"body\":" + BODY + ",\"meta\":" + META + "}";
    private static final String PROTECTED_VALUE = b64(HEADER.getBytes(StandardCharsets.UTF_8));
    private static final String PAYLOAD_VALUE = b64(PAYLOAD.getBytes(StandardCharsets.UTF_8));
    private static final String SIGNATURE_VALUE = b64(filled(64, 0x33));
    private static final String VALID_JSON = wrapper(PROTECTED_VALUE, PAYLOAD_VALUE, SIGNATURE_VALUE);

    private final SignedInnerCodec codec = new SignedInnerCodec();

    @Test
    void preparesExactJcsSegmentsAsTheAsciiSigningInputAndRoundTrips() {
        byte[] data = {0, 1, 2};
        byte[] signature = filled(64, 0x33);
        SignedInnerCodec.Message message = message(
                new ProtocolPayload("application/octet-stream", data, data.length)
        );

        byte[] inner;
        try (SignedInnerCodec.Prepared prepared = codec.prepare(message)) {
            assertEquals(PROTECTED_VALUE, prepared.protectedValue());
            assertEquals(PAYLOAD_VALUE, prepared.payloadValue());
            assertEquals(HEADER, decodeUtf8(prepared.protectedValue()));
            assertEquals(PAYLOAD, decodeUtf8(prepared.payloadValue()));
            assertArrayEquals(
                    (prepared.protectedValue() + "." + prepared.payloadValue())
                            .getBytes(StandardCharsets.US_ASCII),
                    prepared.signingInput()
            );

            inner = codec.assemble(prepared, signature);
        }

        assertEquals(VALID_JSON, new String(inner, StandardCharsets.UTF_8));
        assertArrayEquals(filled(64, 0x33), signature);

        try (SignedInnerCodec.Decoded decoded = codec.decode(inner)) {
            assertMessage(decoded.message(), data);
            assertArrayEquals(
                    (PROTECTED_VALUE + "." + PAYLOAD_VALUE).getBytes(StandardCharsets.US_ASCII),
                    decoded.signingInput()
            );
            assertArrayEquals(signature, decoded.signature());
        }
    }

    @Test
    void decodeVerifiesTheExactReceivedSegmentsWithoutReserializing() {
        String receivedHeader = "{ \"wind_id\" : \"" + MESSAGE_ID + "\","
                + "\"typ\":\"wind+jws\",\"ts\":" + TIMESTAMP + ","
                + "\"kid\":\"" + SIGNING_KID + "\","
                + "\"jwe_recipients_hash\":\"" + HASH_22 + "\","
                + "\"jwe_protected_hash\":\"" + HASH_11 + "\",\"alg\":\"EdDSA\" }";
        String receivedPayload = "{ \"meta\" : " + META + ", \"body\" : " + BODY + " }";
        String receivedProtectedValue = b64(receivedHeader.getBytes(StandardCharsets.UTF_8));
        String receivedPayloadValue = b64(receivedPayload.getBytes(StandardCharsets.UTF_8));
        byte[] expectedInput = (receivedProtectedValue + "." + receivedPayloadValue)
                .getBytes(StandardCharsets.US_ASCII);
        String nonCanonicalWrapper = "{ \"signature\" : \"" + SIGNATURE_VALUE + "\","
                + " \"protected\" : \"" + receivedProtectedValue + "\","
                + " \"payload\" : \"" + receivedPayloadValue + "\" }";

        try (SignedInnerCodec.Decoded decoded = codec.decode(
                nonCanonicalWrapper.getBytes(StandardCharsets.UTF_8))) {
            assertArrayEquals(expectedInput, decoded.signingInput());
            assertMessage(decoded.message(), new byte[]{0, 1, 2});
        }
    }

    @Test
    void supportsBinaryAndEmptyPayloads() {
        byte[] binary = {0, (byte) 0xff, 2, (byte) 0x80};
        roundTripPayload(new ProtocolPayload("application/octet-stream", binary, binary.length), binary);
        roundTripPayload(new ProtocolPayload("application/octet-stream", new byte[0], 0), new byte[0]);
    }

    @Test
    void preparedAndDecodedDefensivelyCopyAndClearOwnedArraysOnIdempotentClose() {
        SignedInnerCodec.Prepared prepared = codec.prepare(message(
                new ProtocolPayload("application/octet-stream", new byte[]{0, 1, 2}, 3)
        ));
        byte[] firstPreparedRead = prepared.signingInput();
        byte[] secondPreparedRead = prepared.signingInput();
        assertNotSame(firstPreparedRead, secondPreparedRead);
        firstPreparedRead[0] ^= 1;
        assertFalse(Arrays.equals(firstPreparedRead, prepared.signingInput()));
        prepared.close();
        prepared.close();
        assertAllZero(prepared.signingInput());

        SignedInnerCodec.Decoded decoded = codec.decode(VALID_JSON.getBytes(StandardCharsets.UTF_8));
        byte[] firstInputRead = decoded.signingInput();
        byte[] firstSignatureRead = decoded.signature();
        firstInputRead[0] ^= 1;
        firstSignatureRead[0] ^= 1;
        assertFalse(Arrays.equals(firstInputRead, decoded.signingInput()));
        assertFalse(Arrays.equals(firstSignatureRead, decoded.signature()));
        decoded.close();
        decoded.close();
        assertAllZero(decoded.signingInput());
        assertAllZero(decoded.signature());
    }

    @Test
    void rejectsInvalidTrustedInputsAndSignatureLengths() {
        ProtocolPayload payload = new ProtocolPayload("application/octet-stream", new byte[0], 0);
        OuterBinding.Hashes binding = new OuterBinding.Hashes(new byte[32], new byte[32]);

        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(null, 0, payload, binding, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message("123E4567-E89B-42D3-A456-426614174000",
                        0, payload, binding, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(MESSAGE_ID, -1, payload, binding, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(MESSAGE_ID, 0, null, binding, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(MESSAGE_ID, 0, payload, null, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(MESSAGE_ID, 0, payload, binding, " "));
        assertThrows(IllegalArgumentException.class,
                () -> new SignedInnerCodec.Message(MESSAGE_ID, 0, payload, binding, b64(new byte[31])));
        assertThrows(IllegalArgumentException.class, () -> codec.prepare(null));

        try (SignedInnerCodec.Prepared prepared = codec.prepare(message(payload))) {
            assertThrows(IllegalArgumentException.class, () -> codec.assemble(null, new byte[64]));
            assertThrows(IllegalArgumentException.class, () -> codec.assemble(prepared, null));
            assertThrows(IllegalArgumentException.class, () -> codec.assemble(prepared, new byte[63]));
            assertThrows(IllegalArgumentException.class, () -> codec.assemble(prepared, new byte[65]));
        }
    }

    @TestFactory
    Stream<DynamicTest> rejectsDuplicatesAtEveryObjectLayerAsMalformed() {
        return malformedCases(List.of(
                named("root", VALID_JSON.replaceFirst("\"payload\":", "\"payload\":" + quote(PAYLOAD_VALUE)
                        + ",\"payload\":")),
                named("protected", withHeader(HEADER.replace("\"alg\":\"EdDSA\",",
                        "\"alg\":\"EdDSA\",\"alg\":\"EdDSA\","))),
                named("payload", withPayload(PAYLOAD.replace("\"body\":" + BODY + ",",
                        "\"body\":" + BODY + ",\"body\":" + BODY + ","))),
                named("meta", withPayload(PAYLOAD.replace("\"content_type\":\"application/octet-stream\",",
                        "\"content_type\":\"application/octet-stream\","
                                + "\"content_type\":\"application/octet-stream\","))),
                named("body", withPayload(PAYLOAD.replace("\"data\":\"AAEC\"",
                        "\"data\":\"AAEC\",\"data\":\"AAEC\"")))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsUnknownFieldsAtEveryObjectLayerAsInvalidField() {
        return invalidCases(List.of(
                named("root", VALID_JSON.substring(0, VALID_JSON.length() - 1) + ",\"extra\":0}"),
                named("protected", withHeader(HEADER.substring(0, HEADER.length() - 1) + ",\"extra\":0}")),
                named("payload", withPayload(PAYLOAD.substring(0, PAYLOAD.length() - 1) + ",\"extra\":0}")),
                named("meta", withPayload(PAYLOAD.replace("\"original_size\":3}",
                        "\"original_size\":3,\"extra\":0}"))),
                named("body", withPayload(PAYLOAD.replace("\"data\":\"AAEC\"}",
                        "\"data\":\"AAEC\",\"extra\":0}")))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsMissingFieldsAtEveryObjectLayerAsInvalidField() {
        return invalidCases(List.of(
                named("root", "{\"protected\":" + quote(PROTECTED_VALUE)
                        + ",\"signature\":" + quote(SIGNATURE_VALUE) + "}"),
                named("protected", withHeader(HEADER.replace("\"typ\":\"wind+jws\",", ""))),
                named("payload", withPayload(PAYLOAD.replace("\"body\":" + BODY + ",", ""))),
                named("meta", withPayload(PAYLOAD.replace(
                        "\"content_type\":\"application/octet-stream\",", ""))),
                named("body", withPayload(PAYLOAD.replace("\"data\":\"AAEC\"", "")))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsNullAndWrongTypesAtEveryObjectLayerAsMalformed() {
        return malformedCases(List.of(
                named("null root", "null"),
                named("array root", "[]"),
                named("null protected segment", VALID_JSON.replace(quote(PROTECTED_VALUE), "null")),
                named("object protected segment", VALID_JSON.replace(quote(PROTECTED_VALUE), "{}")),
                named("null payload segment", VALID_JSON.replace(quote(PAYLOAD_VALUE), "null")),
                named("number payload segment", VALID_JSON.replace(quote(PAYLOAD_VALUE), "0")),
                named("null signature", VALID_JSON.replace(quote(SIGNATURE_VALUE), "null")),
                named("array signature", VALID_JSON.replace(quote(SIGNATURE_VALUE), "[]")),
                named("null protected field", withHeader(HEADER.replace("\"alg\":\"EdDSA\"", "\"alg\":null"))),
                named("wrong protected field type", withHeader(HEADER.replace(
                        "\"ts\":" + TIMESTAMP, "\"ts\":\"" + TIMESTAMP + "\""))),
                named("null payload object", withPayload("null")),
                named("wrong payload object type", withPayload("[]")),
                named("null meta", withPayload(PAYLOAD.replace(META, "null"))),
                named("wrong body type", withPayload(PAYLOAD.replace(BODY, "0"))),
                named("null meta field", withPayload(PAYLOAD.replace(
                        "\"content_type\":\"application/octet-stream\"", "\"content_type\":null"))),
                named("wrong body field type", withPayload(PAYLOAD.replace("\"data\":\"AAEC\"", "\"data\":3")))
        ));
    }

    @Test
    void rejectsTrailingMalformedAndNonUtf8JsonAtEveryEncodedLayer() {
        assertError(ErrorCode.MALFORMED_WIRE, (VALID_JSON + " true").getBytes(StandardCharsets.UTF_8));
        assertError(ErrorCode.MALFORMED_WIRE,
                new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '(', '"', '}'});
        assertError(ErrorCode.MALFORMED_WIRE, withProtectedBytes(
                (HEADER + " true").getBytes(StandardCharsets.UTF_8)));
        assertError(ErrorCode.MALFORMED_WIRE, withProtectedBytes(
                new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '(', '"', '}'}));
        assertError(ErrorCode.MALFORMED_WIRE, withPayloadBytes(
                (PAYLOAD + " true").getBytes(StandardCharsets.UTF_8)));
        assertError(ErrorCode.MALFORMED_WIRE, withPayloadBytes(
                new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '(', '"', '}'}));
    }

    @TestFactory
    Stream<DynamicTest> rejectsUtf16AndUtf32JsonAtEveryEncodedLayer() {
        return Stream.of("UTF-16BE", "UTF-16LE", "UTF-32BE", "UTF-32LE")
                .flatMap(charsetName -> {
                    Charset charset = Charset.forName(charsetName);
                    return Stream.of(
                            dynamicError(charsetName + " root wrapper",
                                    VALID_JSON.getBytes(charset), ErrorCode.MALFORMED_WIRE),
                            dynamicError(charsetName + " protected header",
                                    withProtectedBytes(HEADER.getBytes(charset)), ErrorCode.MALFORMED_WIRE),
                            dynamicError(charsetName + " payload",
                                    withPayloadBytes(PAYLOAD.getBytes(charset)), ErrorCode.MALFORMED_WIRE)
                    );
                });
    }

    @TestFactory
    Stream<DynamicTest> rejectsNonCanonicalBase64UrlAtEverySegment() {
        return Stream.of(
                dynamicError("empty protected", replaceProtected(""), ErrorCode.INVALID_FIELD),
                dynamicError("padded protected", replaceProtected(PROTECTED_VALUE + "="), ErrorCode.INVALID_FIELD),
                dynamicError("whitespace protected", replaceProtected(PROTECTED_VALUE + " "), ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet protected", replaceProtected(PROTECTED_VALUE + "+"), ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical protected", replaceProtected("AB"), ErrorCode.INVALID_FIELD),
                dynamicError("empty payload", replacePayload(""), ErrorCode.INVALID_FIELD),
                dynamicError("padded payload", replacePayload(PAYLOAD_VALUE + "="), ErrorCode.INVALID_FIELD),
                dynamicError("whitespace payload", replacePayload(PAYLOAD_VALUE + " "), ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet payload", replacePayload(PAYLOAD_VALUE + "+"), ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical payload", replacePayload("AB"), ErrorCode.INVALID_FIELD),
                dynamicError("empty signature", replaceSignature(""), ErrorCode.INVALID_FIELD),
                dynamicError("padded signature", replaceSignature(SIGNATURE_VALUE + "="), ErrorCode.INVALID_FIELD),
                dynamicError("whitespace signature", replaceSignature(SIGNATURE_VALUE + " "), ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet signature", replaceSignature(SIGNATURE_VALUE + "+"), ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical signature", replaceSignature("AB"), ErrorCode.INVALID_FIELD),
                dynamicError("empty kid", withHeader(HEADER.replace(SIGNING_KID, "")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("padded kid", withHeader(HEADER.replace(SIGNING_KID, SIGNING_KID + "=")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("whitespace kid", withHeader(HEADER.replace(SIGNING_KID, SIGNING_KID + " ")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet kid", withHeader(HEADER.replace(SIGNING_KID, SIGNING_KID + "+")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical kid", withHeader(HEADER.replace(SIGNING_KID, "AB")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("empty hash", withHeader(HEADER.replace(HASH_11, "")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("padded hash", withHeader(HEADER.replace(HASH_11, HASH_11 + "=")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("whitespace hash", withHeader(HEADER.replace(HASH_11, HASH_11 + " ")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet hash", withHeader(HEADER.replace(HASH_11, HASH_11 + "+")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical hash", withHeader(HEADER.replace(HASH_11, "AB")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("padded payload data", withPayload(PAYLOAD.replace("AAEC", "AAEC=")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("whitespace payload data", withPayload(PAYLOAD.replace("AAEC", "AAEC ")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("invalid alphabet payload data", withPayload(PAYLOAD.replace("AAEC", "AA+C")),
                        ErrorCode.INVALID_FIELD),
                dynamicError("non-canonical payload data", withPayload(PAYLOAD.replace("AAEC", "AB")),
                        ErrorCode.INVALID_FIELD)
        );
    }

    @TestFactory
    Stream<DynamicTest> rejectsWrongFixedValuesAndEncodedLengths() {
        String kid31 = b64(new byte[31]);
        String kid33 = b64(new byte[33]);
        String hash31 = b64(new byte[31]);
        String hash33 = b64(new byte[33]);
        return invalidCases(List.of(
                named("wrong typ", withHeader(HEADER.replace("\"typ\":\"wind+jws\"", "\"typ\":\"wind+inner\""))),
                named("wrong alg", withHeader(HEADER.replace("\"alg\":\"EdDSA\"", "\"alg\":\"Ed25519\""))),
                named("kid 31", withHeader(HEADER.replace(SIGNING_KID, kid31))),
                named("kid 33", withHeader(HEADER.replace(SIGNING_KID, kid33))),
                named("protected hash 31", withHeader(HEADER.replace(HASH_11, hash31))),
                named("protected hash 33", withHeader(HEADER.replace(HASH_11, hash33))),
                named("recipients hash 31", withHeader(HEADER.replace(HASH_22, hash31))),
                named("recipients hash 33", withHeader(HEADER.replace(HASH_22, hash33))),
                named("signature 63", replaceSignature(b64(new byte[63]))),
                named("signature 65", replaceSignature(b64(new byte[65])))
        ));
    }

    @TestFactory
    Stream<DynamicTest> rejectsInvalidTimestampUuidAndPayloadMetadata() {
        return invalidCases(List.of(
                named("negative timestamp", withHeader(withTimestamp("-1"))),
                named("timestamp above safe integer", withHeader(withTimestamp("9007199254740992"))),
                named("decimal timestamp", withHeader(withTimestamp("1.0"))),
                named("exponent timestamp", withHeader(withTimestamp("1e0"))),
                named("uppercase UUID", withHeader(HEADER.replace(MESSAGE_ID,
                        "123E4567-E89B-42D3-A456-426614174000"))),
                named("UUID v1", withHeader(HEADER.replace(MESSAGE_ID,
                        "123e4567-e89b-12d3-a456-426614174000"))),
                named("wrong UUID variant", withHeader(HEADER.replace(MESSAGE_ID,
                        "123e4567-e89b-42d3-7456-426614174000"))),
                named("blank content type", withPayload(PAYLOAD.replace(
                        "\"content_type\":\"application/octet-stream\"", "\"content_type\":\" \""))),
                named("negative original size", withPayload(PAYLOAD.replace("\"original_size\":3", "\"original_size\":-1"))),
                named("size mismatch", withPayload(PAYLOAD.replace("\"original_size\":3", "\"original_size\":4"))),
                named("size overflow", withPayload(PAYLOAD.replace("\"original_size\":3", "\"original_size\":8388609"))),
                named("decimal original size", withPayload(PAYLOAD.replace("\"original_size\":3", "\"original_size\":3.0")))
        ));
    }

    @Test
    void rejectsPayloadAndInnerInputsAboveStageLimits() {
        byte[] oversizedPayload = new byte[ProtocolLimits.MAX_PAYLOAD_BYTES + 1];
        String oversizedPayloadJson = PAYLOAD
                .replace("\"AAEC\"", quote(b64(oversizedPayload)))
                .replace("\"original_size\":3", "\"original_size\":" + oversizedPayload.length);

        assertError(ErrorCode.INVALID_FIELD,
                withPayload(oversizedPayloadJson).getBytes(StandardCharsets.UTF_8));
        assertError(ErrorCode.INVALID_FIELD, new byte[ProtocolLimits.MAX_INNER_BYTES + 1]);
    }

    private void roundTripPayload(ProtocolPayload payload, byte[] expected) {
        byte[] signature = filled(64, 0x33);
        try (SignedInnerCodec.Prepared prepared = codec.prepare(message(payload))) {
            byte[] inner = codec.assemble(prepared, signature);
            try (SignedInnerCodec.Decoded decoded = codec.decode(inner)) {
                assertArrayEquals(expected, decoded.message().payload().data());
                assertEquals(expected.length, decoded.message().payload().originalSize());
            }
        }
    }

    private void assertMessage(SignedInnerCodec.Message message, byte[] expectedData) {
        assertEquals(MESSAGE_ID, message.messageId());
        assertEquals(TIMESTAMP, message.timestamp());
        assertEquals(SIGNING_KID, message.signingKid());
        assertEquals("application/octet-stream", message.payload().contentType());
        assertEquals(expectedData.length, message.payload().originalSize());
        assertArrayEquals(expectedData, message.payload().data());
        assertArrayEquals(filled(32, 0x11), message.binding().protectedHash());
        assertArrayEquals(filled(32, 0x22), message.binding().recipientsHash());
    }

    private Stream<DynamicTest> malformedCases(List<NamedJson> cases) {
        return cases.stream().map(value -> DynamicTest.dynamicTest(value.name(),
                () -> assertError(ErrorCode.MALFORMED_WIRE, value.json().getBytes(StandardCharsets.UTF_8))));
    }

    private Stream<DynamicTest> invalidCases(List<NamedJson> cases) {
        return cases.stream().map(value -> DynamicTest.dynamicTest(value.name(),
                () -> assertError(ErrorCode.INVALID_FIELD, value.json().getBytes(StandardCharsets.UTF_8))));
    }

    private DynamicTest dynamicError(String name, String json, ErrorCode expected) {
        return DynamicTest.dynamicTest(name,
                () -> assertError(expected, json.getBytes(StandardCharsets.UTF_8)));
    }

    private DynamicTest dynamicError(String name, byte[] bytes, ErrorCode expected) {
        return DynamicTest.dynamicTest(name, () -> assertError(expected, bytes));
    }

    private static NamedJson named(String name, String json) {
        return new NamedJson(name, json);
    }

    private void assertError(ErrorCode expected, byte[] bytes) {
        ProtocolException failure = assertThrows(ProtocolException.class, () -> codec.decode(bytes));
        assertEquals(expected, failure.errorCode());
    }

    private static SignedInnerCodec.Message message(ProtocolPayload payload) {
        return new SignedInnerCodec.Message(
                MESSAGE_ID,
                TIMESTAMP,
                payload,
                new OuterBinding.Hashes(filled(32, 0x11), filled(32, 0x22)),
                SIGNING_KID
        );
    }

    private static String withHeader(String header) {
        return wrapper(b64(header.getBytes(StandardCharsets.UTF_8)), PAYLOAD_VALUE, SIGNATURE_VALUE);
    }

    private static String withPayload(String payload) {
        return wrapper(PROTECTED_VALUE, b64(payload.getBytes(StandardCharsets.UTF_8)), SIGNATURE_VALUE);
    }

    private static byte[] withProtectedBytes(byte[] headerBytes) {
        return replaceProtected(b64(headerBytes)).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] withPayloadBytes(byte[] payloadBytes) {
        return replacePayload(b64(payloadBytes)).getBytes(StandardCharsets.UTF_8);
    }

    private static String replaceProtected(String value) {
        return wrapper(value, PAYLOAD_VALUE, SIGNATURE_VALUE);
    }

    private static String replacePayload(String value) {
        return wrapper(PROTECTED_VALUE, value, SIGNATURE_VALUE);
    }

    private static String replaceSignature(String value) {
        return wrapper(PROTECTED_VALUE, PAYLOAD_VALUE, value);
    }

    private static String withTimestamp(String timestamp) {
        return HEADER.replace("\"ts\":" + TIMESTAMP, "\"ts\":" + timestamp);
    }

    private static String wrapper(String protectedValue, String payloadValue, String signatureValue) {
        return "{\"payload\":" + quote(payloadValue)
                + ",\"protected\":" + quote(protectedValue)
                + ",\"signature\":" + quote(signatureValue) + "}";
    }

    private static String quote(String value) {
        return "\"" + value + "\"";
    }

    private static String decodeUtf8(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static void assertAllZero(byte[] value) {
        assertTrue(Arrays.equals(new byte[value.length], value));
    }

    private record NamedJson(String name, String json) {
    }
}
