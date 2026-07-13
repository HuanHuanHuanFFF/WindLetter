package com.windletter.protocol.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class OuterJsonMapperTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String KID_ONE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    private static final String KID_TWO = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    @Test
    void projectsProtectedHeadersWithExactlyOneSenderRepresentation() throws Exception {
        ProtectedHeader publicHeader = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "public", "A256GCM", "X25519",
                new SenderKid(KID_ONE)
        );
        ObjectNode publicJson = OuterJsonMapper.toProtectedJson(publicHeader);

        assertEquals(MAPPER.readTree("""
                {
                  "typ":"wind+jwe",
                  "cty":"wind+inner",
                  "ver":"1.0",
                  "wind_mode":"public",
                  "enc":"A256GCM",
                  "key_alg":"X25519",
                  "kid":{"x25519":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}
                }
                """), publicJson);
        assertFalse(publicJson.has("epk"));

        byte[] ephemeralPublicKey = filled(32, 0x03);
        ProtectedHeader obfuscationHeader = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "obfuscation", "A256GCM", "X25519",
                new Epk("OKP", "X25519", ephemeralPublicKey)
        );
        ObjectNode obfuscationJson = OuterJsonMapper.toProtectedJson(obfuscationHeader);

        assertEquals(MAPPER.readTree("""
                {
                  "typ":"wind+jwe",
                  "cty":"wind+inner",
                  "ver":"1.0",
                  "wind_mode":"obfuscation",
                  "enc":"A256GCM",
                  "key_alg":"X25519",
                  "epk":{"kty":"OKP","crv":"X25519","x":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}
                }
                """), obfuscationJson);
        assertFalse(obfuscationJson.has("kid"));
    }

    @Test
    void projectsTwoRecipientCanonicalVectorAndPreservesArrayOrder() {
        PublicRecipient first = new PublicRecipient(
                new RecipientKid(KID_ONE, null), filled(40, 0x11), null
        );
        PublicRecipient second = new PublicRecipient(
                new RecipientKid(KID_TWO, null), filled(40, 0x22), null
        );

        ArrayNode projected = OuterJsonMapper.toRecipientsJson(List.of(first, second));
        String canonical = new String(JcsCanonicalizer.canonicalize(projected), StandardCharsets.UTF_8);

        assertEquals("[{\"encrypted_key\":\"EREREREREREREREREREREREREREREREREREREREREREREREREREREQ\",\"kid\":{\"x25519\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"}},{\"encrypted_key\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg\",\"kid\":{\"x25519\":\"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI\"}}]", canonical);
        String reversed = new String(
                JcsCanonicalizer.canonicalize(OuterJsonMapper.toRecipientsJson(List.of(second, first))),
                StandardCharsets.UTF_8
        );
        assertNotEquals(canonical, reversed);
        assertEquals(KID_ONE, projected.get(0).path("kid").path("x25519").textValue());
        assertEquals(KID_TWO, projected.get(1).path("kid").path("x25519").textValue());
    }

    @Test
    void projectsPublicAndObfuscationRecipientConditionalFieldsWithoutNulls() {
        byte[] encryptedKey = filled(40, 0x11);
        byte[] encapsulation = filled(8, 0x44);
        byte[] rid = filled(16, 0x55);

        ArrayNode recipients = OuterJsonMapper.toRecipientsJson(List.of(
                new PublicRecipient(new RecipientKid(KID_ONE, null), encryptedKey, null),
                new PublicRecipient(new RecipientKid(KID_ONE, KID_TWO), encryptedKey, encapsulation),
                new ObfuscationRecipient(rid, encryptedKey, null),
                new ObfuscationRecipient(rid, encryptedKey, encapsulation)
        ));

        JsonNode publicX25519 = recipients.get(0);
        assertEquals(2, publicX25519.size());
        assertEquals(1, publicX25519.path("kid").size());
        assertFalse(publicX25519.has("rid"));
        assertFalse(publicX25519.has("ek"));

        JsonNode publicHybrid = recipients.get(1);
        assertEquals(KID_TWO, publicHybrid.path("kid").path("mlkem768").textValue());
        assertEquals(Base64Url.encode(encapsulation), publicHybrid.path("ek").textValue());
        assertFalse(publicHybrid.has("rid"));

        JsonNode obfuscationX25519 = recipients.get(2);
        assertEquals(Base64Url.encode(rid), obfuscationX25519.path("rid").textValue());
        assertFalse(obfuscationX25519.has("kid"));
        assertFalse(obfuscationX25519.has("ek"));

        JsonNode obfuscationHybrid = recipients.get(3);
        assertEquals(Base64Url.encode(encapsulation), obfuscationHybrid.path("ek").textValue());
        assertFalse(obfuscationHybrid.has("kid"));
    }

    @Test
    void projectsOuterUsingExactProtectedAndAadStringsAndUnpaddedBase64Url() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "public", "A256GCM", "X25519",
                new SenderKid(KID_ONE)
        );
        PublicRecipient recipient = new PublicRecipient(
                new RecipientKid(KID_ONE, null), filled(40, 0x11), null
        );
        WindLetter letter = new WindLetter(
                header,
                "protected-exact",
                "aad-exact",
                List.of(recipient),
                new byte[]{0x00, 0x01, 0x02},
                new byte[0],
                new byte[]{(byte) 0xff}
        );

        ObjectNode outer = OuterJsonMapper.toOuterJson(letter);

        assertEquals(6, outer.size());
        assertEquals("protected-exact", outer.path("protected").textValue());
        assertEquals("aad-exact", outer.path("aad").textValue());
        assertEquals(OuterJsonMapper.toRecipientsJson(List.of(recipient)), outer.path("recipients"));
        assertEquals("AAEC", outer.path("iv").textValue());
        assertEquals("", outer.path("ciphertext").textValue());
        assertEquals("_w", outer.path("tag").textValue());
        assertFalse(outer.has("protectedHeader"));
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
