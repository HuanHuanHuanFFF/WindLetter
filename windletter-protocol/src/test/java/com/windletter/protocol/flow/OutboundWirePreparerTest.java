package com.windletter.protocol.flow;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.binding.AadService;
import com.windletter.protocol.binding.JcsAadService;
import com.windletter.protocol.validation.DefaultOuterWireValidator;
import com.windletter.protocol.validation.OuterWireValidator;
import com.windletter.protocol.wire.JacksonOuterWireCodec;
import com.windletter.protocol.wire.KidRef;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.OuterWireCodec;
import com.windletter.protocol.wire.ParsedOuterWire;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import java.util.List;
import org.junit.jupiter.api.Test;

class OutboundWirePreparerTest {

    private final AadService aadService = new JcsAadService();
    private final OutboundWirePreparer preparer = new DefaultOutboundWirePreparer();
    private final OuterWireValidator validator = new DefaultOuterWireValidator();
    private final OuterWireCodec codec = new JacksonOuterWireCodec();

    @Test
    void shouldPrepareMessageWithAutoComputedAad() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe",
                "wind+jws",
                "1.0",
                "public",
                "A256GCM",
                "X25519",
                null,
                null);
        List<RecipientEntry> recipients = List.of(
                new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1"));

        OuterWireMessage wire = preparer.prepare(header, recipients, "aXY", "Y3Q", "dGFn");
        ParsedOuterWire parsed = codec.parseWithRaw(codec.serialize(wire));
        String expectedAad = aadService.computeAadBase64Url(recipients);

        assertEquals(expectedAad, wire.aadB64());
        assertDoesNotThrow(() -> validator.validateStructure(wire));
        assertDoesNotThrow(() -> validator.validateAadConsistency(parsed));
    }

    @Test
    void shouldRejectMissingRequiredOutboundField() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe",
                "wind+jws",
                "1.0",
                "public",
                "A256GCM",
                "X25519",
                null,
                null);
        List<RecipientEntry> recipients = List.of(
                new RecipientEntry(new KidRef("kid-r1", null), null, null, "enc-r1"));

        ProtocolException ex = assertThrows(
                ProtocolException.class,
                () -> preparer.prepare(header, recipients, " ", "Y3Q", "dGFn"));
        assertEquals(ErrorCode.INVALID_FIELD, ex.errorCode());
    }
}
