package com.windletter.protocol.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.binding.AadService;
import com.windletter.protocol.binding.JcsAadService;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.parser.OuterWireParser;
import com.windletter.protocol.wire.JacksonOuterWireCodec;
import com.windletter.protocol.wire.KidRef;
import com.windletter.protocol.wire.OuterWireCodec;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ParsedOuterWire;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultOuterWireValidatorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AadService aadService = new JcsAadService();
    private final OuterWireValidator validator = new DefaultOuterWireValidator(objectMapper, aadService);
    private final OuterWireParser parser = new JacksonOuterWireParser(objectMapper);
    private final OuterWireCodec codec = new JacksonOuterWireCodec(objectMapper);

    @Test
    void shouldPassForValidWireStructureAndAad() {
        OuterWireMessage wire = validWire("1.0", "X25519", null);
        ParsedOuterWire parsed = codec.parseWithRaw(codec.serialize(wire));

        assertDoesNotThrow(() -> validator.validateStructure(wire));
        assertDoesNotThrow(() -> validator.validateAadConsistency(parsed));
    }

    @Test
    void shouldReturnAadMismatchWhenRecipientsTampered() {
        OuterWireMessage valid = validWire("1.0", "X25519", null);
        RecipientEntry tamperedEntry = new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1-tampered");
        OuterWireMessage tampered = new OuterWireMessage(
                valid.protectedB64(),
                valid.aadB64(),
                List.of(tamperedEntry),
                valid.ivB64(),
                valid.ciphertextB64(),
                valid.tagB64());
        ParsedOuterWire parsedTampered = codec.parseWithRaw(codec.serialize(tampered));

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateAadConsistency(parsedTampered));
        assertEquals(ErrorCode.AAD_MISMATCH, ex.errorCode());
    }

    @Test
    void shouldReturnMalformedWireWhenProtectedIsNotDecodableJson() {
        OuterWireMessage wire = new OuterWireMessage(
                "@@@",
                "aad",
                List.of(new RecipientEntry(null, null, null, "enc-r1")),
                "aXY",
                "Y3Q",
                "dGFn");

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldReturnUnsupportedVersionWhenVersionInvalid() {
        OuterWireMessage wire = validWire("2.0", "X25519", null);

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.UNSUPPORTED_VERSION, ex.errorCode());
    }

    @Test
    void shouldReturnUnsupportedAlgorithmWhenKeyAlgInvalid() {
        OuterWireMessage wire = validWire("1.0", "RSA-OAEP", null);

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void shouldReturnInvalidFieldWhenRequiredFieldMissing() {
        OuterWireMessage valid = validWire("1.0", "X25519", null);
        OuterWireMessage missingIv = new OuterWireMessage(
                valid.protectedB64(),
                valid.aadB64(),
                valid.recipients(),
                " ",
                valid.ciphertextB64(),
                valid.tagB64());

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(missingIv));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldValidateAadFromRawRecipientsNodeWhenOptionalFieldsAreAbsent() throws Exception {
        String protectedB64 = base64UrlJson(new ProtectedHeader(
                "wind+jwe",
                "wind+jws",
                "1.0",
                "public",
                "A256GCM",
                "X25519",
                null,
                null));
        String recipientsJson = """
                [
                  {
                    "encrypted_key": "enc-r1"
                  }
                ]
                """;
        String aad = aadService.computeAadBase64Url(objectMapper.readTree(recipientsJson));
        String wireJson = """
                {
                  "protected":"%s",
                  "aad":"%s",
                  "recipients":%s,
                  "iv":"aXY",
                  "ciphertext":"Y3Q",
                  "tag":"dGFn"
                }
                """.formatted(protectedB64, aad, recipientsJson);

        ParsedOuterWire parsed = parser.parseWithRaw(wireJson);

        assertDoesNotThrow(() -> validator.validateAadConsistency(parsed));
    }

    private OuterWireMessage validWire(String version, String keyAlg, String forcedAad) {
        List<RecipientEntry> recipients = List.of(new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1"));
        String aad = forcedAad != null ? forcedAad : aadService.computeAadBase64Url(recipients);
        ProtectedHeader protectedHeader = new ProtectedHeader(
                "wind+jwe",
                "wind+jws",
                version,
                "public",
                "A256GCM",
                keyAlg,
                null,
                null);

        return new OuterWireMessage(
                base64UrlJson(protectedHeader),
                aad,
                recipients,
                "aXY",
                "Y3Q",
                "dGFn");
    }

    private String base64UrlJson(Object value) {
        try {
            byte[] json = objectMapper.writeValueAsBytes(value);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (Exception e) {
            throw new AssertionError("failed to build test input", e);
        }
    }
}
