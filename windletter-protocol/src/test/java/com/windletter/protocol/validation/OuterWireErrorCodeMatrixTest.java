package com.windletter.protocol.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class OuterWireErrorCodeMatrixTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AadService aadService = new JcsAadService();
    private final OuterWireValidator validator = new DefaultOuterWireValidator(objectMapper, aadService);
    private final OuterWireParser parser = new JacksonOuterWireParser(objectMapper);
    private final OuterWireCodec codec = new JacksonOuterWireCodec(objectMapper);

    @Test
    void shouldMapMalformedJsonToMalformedWire() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse("{"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldMapTypeMismatchToInvalidField() {
        String wireJson = """
                {
                  "protected":"%s",
                  "aad":"W10",
                  "recipients":"not-array",
                  "iv":"aXY",
                  "ciphertext":"Y3Q",
                  "tag":"dGFn"
                }
                """.formatted(validProtectedB64("1.0", "wind+jws", "public", "A256GCM", "X25519"));

        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(wireJson));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapNonObjectProtectedToMalformedWire() {
        String protectedNotObject = Base64.getUrlEncoder().withoutPadding().encodeToString("\"x\"".getBytes());
        OuterWireMessage wire = new OuterWireMessage(
                protectedNotObject,
                "W10",
                List.of(new RecipientEntry(null, null, null, "enc-r1")),
                "aXY",
                "Y3Q",
                "dGFn");

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    @Test
    void shouldMapRecipientsMissingToInvalidField() {
        String wireJsonMissingRecipients = """
                {
                  "protected":"%s",
                  "aad":"W10",
                  "iv":"aXY",
                  "ciphertext":"Y3Q",
                  "tag":"dGFn"
                }
                """.formatted(validProtectedB64("1.0", "wind+jws", "public", "A256GCM", "X25519"));
        OuterWireMessage wire = parser.parse(wireJsonMissingRecipients);
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapRecipientsNullToInvalidField() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A256GCM", "X25519", null, "W10");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapRecipientsEmptyToInvalidField() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A256GCM", "X25519", List.of(), "W10");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapIllegalAadEncodingToInvalidField() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A256GCM", "X25519", defaultRecipients(), "a+b");
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapUnsupportedVersion() {
        OuterWireMessage wire = validWire("2.0", "wind+jws", "public", "A256GCM", "X25519", defaultRecipients(), defaultAad(defaultRecipients()));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.UNSUPPORTED_VERSION, ex.errorCode());
    }

    @Test
    void shouldMapUnsupportedEnc() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A128GCM", "X25519", defaultRecipients(), defaultAad(defaultRecipients()));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void shouldMapUnsupportedKeyAlg() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A256GCM", "RSA-OAEP", defaultRecipients(), defaultAad(defaultRecipients()));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());
    }

    @Test
    void shouldMapInvalidCty() {
        OuterWireMessage wire = validWire("1.0", "application/json", "public", "A256GCM", "X25519", defaultRecipients(), defaultAad(defaultRecipients()));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapInvalidWindMode() {
        OuterWireMessage wire = validWire("1.0", "wind+jws", "broadcast", "A256GCM", "X25519", defaultRecipients(), defaultAad(defaultRecipients()));
        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateStructure(wire));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }

    @Test
    void shouldMapAadMismatch() {
        List<RecipientEntry> original = defaultRecipients();
        List<RecipientEntry> tampered = List.of(new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1-x"));
        String aad = defaultAad(original);
        OuterWireMessage wire = validWire("1.0", "wind+jws", "public", "A256GCM", "X25519", tampered, aad);
        ParsedOuterWire parsed = codec.parseWithRaw(codec.serialize(wire));

        ProtocolException ex = assertThrows(ProtocolException.class, () -> validator.validateAadConsistency(parsed));
        assertEquals(ErrorCode.AAD_MISMATCH, ex.errorCode());
    }

    private String validProtectedB64(String ver, String cty, String mode, String enc, String keyAlg) {
        ProtectedHeader header = new ProtectedHeader("wind+jwe", cty, ver, mode, enc, keyAlg, null, null);
        try {
            byte[] json = objectMapper.writeValueAsBytes(header);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (Exception e) {
            throw new AssertionError("failed to build protected header", e);
        }
    }

    private OuterWireMessage validWire(
            String ver,
            String cty,
            String mode,
            String enc,
            String keyAlg,
            List<RecipientEntry> recipients,
            String aad) {
        return new OuterWireMessage(
                validProtectedB64(ver, cty, mode, enc, keyAlg),
                aad,
                recipients,
                "aXY",
                "Y3Q",
                "dGFn");
    }

    private List<RecipientEntry> defaultRecipients() {
        return List.of(new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1"));
    }

    private String defaultAad(List<RecipientEntry> recipients) {
        return aadService.computeAadBase64Url(recipients);
    }
}
