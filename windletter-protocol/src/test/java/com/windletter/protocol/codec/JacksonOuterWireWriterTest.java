package com.windletter.protocol.codec;

import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class JacksonOuterWireWriterTest {

    private static final String KID_ONE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    private static final String KID_TWO = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    @Test
    void writesTypedOuterWireThatRoundTripsThroughTheStrictParserWithoutChangingWireValues() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "public", "A256GCM", "X25519",
                new SenderKid(KID_ONE)
        );
        List<RecipientEntry> recipients = List.of(
                new PublicRecipient(new RecipientKid(KID_ONE, null), filled(40, 0x11), null),
                new PublicRecipient(new RecipientKid(KID_TWO, null), filled(40, 0x22), null)
        );
        String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                OuterJsonMapper.toProtectedJson(header)
        ));
        String aad = new OuterAad().compute(recipients);
        WindLetter original = new WindLetter(
                header, protectedValue, aad, recipients,
                filled(12, 0x33), filled(24, 0x44), filled(16, 0x55)
        );

        String wire = new JacksonOuterWireWriter().write(original);
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);

        assertEquals(original.protectedHeader(), parsed.protectedHeader());
        assertEquals(protectedValue, parsed.protectedValue());
        assertEquals(aad, parsed.aad());
        assertEquals(2, parsed.recipients().size());
        assertRecipientEquals((PublicRecipient) original.recipients().get(0), (PublicRecipient) parsed.recipients().get(0));
        assertRecipientEquals((PublicRecipient) original.recipients().get(1), (PublicRecipient) parsed.recipients().get(1));
        assertArrayEquals(original.iv(), parsed.iv());
        assertArrayEquals(original.ciphertext(), parsed.ciphertext());
        assertArrayEquals(original.tag(), parsed.tag());
    }

    @Test
    void writesEightEntryObfuscationX25519OuterWireThatRoundTripsWithoutChangingAnyRecipientValue() {
        Epk epk = new Epk("OKP", "X25519", filled(32, 0x10));
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "obfuscation", "A256GCM", "X25519", epk
        );
        List<RecipientEntry> recipients = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            recipients.add(new ObfuscationRecipient(
                    filled(16, 0x20 + i),
                    filled(40, 0x30 + i),
                    null
            ));
        }
        String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                OuterJsonMapper.toProtectedJson(header)
        ));
        String aad = new OuterAad().compute(recipients);
        WindLetter original = new WindLetter(
                header, protectedValue, aad, recipients,
                filled(12, 0x40), filled(24, 0x50), filled(16, 0x60)
        );

        String wire = new JacksonOuterWireWriter().write(original);
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);

        assertEquals(header.typ(), parsed.protectedHeader().typ());
        assertEquals(header.cty(), parsed.protectedHeader().cty());
        assertEquals(header.ver(), parsed.protectedHeader().ver());
        assertEquals(header.windMode(), parsed.protectedHeader().windMode());
        assertEquals(header.enc(), parsed.protectedHeader().enc());
        assertEquals(header.keyAlg(), parsed.protectedHeader().keyAlg());
        Epk parsedEpk = assertInstanceOf(Epk.class, parsed.protectedHeader().senderInfo());
        assertEquals(epk.kty(), parsedEpk.kty());
        assertEquals(epk.crv(), parsedEpk.crv());
        assertArrayEquals(epk.x(), parsedEpk.x());
        assertEquals(protectedValue, parsed.protectedValue());
        assertEquals(aad, parsed.aad());
        assertEquals(8, parsed.recipients().size());
        for (int i = 0; i < recipients.size(); i++) {
            assertObfuscationRecipientEquals(
                    (ObfuscationRecipient) recipients.get(i),
                    assertInstanceOf(ObfuscationRecipient.class, parsed.recipients().get(i))
            );
        }
        assertArrayEquals(original.iv(), parsed.iv());
        assertArrayEquals(original.ciphertext(), parsed.ciphertext());
        assertArrayEquals(original.tag(), parsed.tag());
    }

    private static void assertRecipientEquals(PublicRecipient expected, PublicRecipient actual) {
        assertEquals(expected.kid(), actual.kid());
        assertArrayEquals(expected.encryptedKey(), actual.encryptedKey());
        assertArrayEquals(expected.ek(), actual.ek());
    }

    private static void assertObfuscationRecipientEquals(
            ObfuscationRecipient expected,
            ObfuscationRecipient actual
    ) {
        assertArrayEquals(expected.rid(), actual.rid());
        assertArrayEquals(expected.encryptedKey(), actual.encryptedKey());
        assertArrayEquals(expected.ek(), actual.ek());
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
