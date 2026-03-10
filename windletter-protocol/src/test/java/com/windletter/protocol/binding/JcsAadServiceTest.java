package com.windletter.protocol.binding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.protocol.wire.KidRef;
import com.windletter.protocol.wire.RecipientEntry;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;

class JcsAadServiceTest {

    private final AadService aadService = new JcsAadService(new Rfc8785JcsCanonicalizer());

    @Test
    void shouldComputeBase64UrlOfCanonicalizedRecipients() throws Exception {
        List<RecipientEntry> recipients = List.of(
                new RecipientEntry(new KidRef("kid-x", "kid-pq"), null, null, "enc-key-1"));

        String rawJson = new ObjectMapper().writeValueAsString(recipients);
        String canonical = new JsonCanonicalizer(rawJson).getEncodedString();
        String expected = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(canonical.getBytes(StandardCharsets.UTF_8));

        assertEquals(expected, aadService.computeAadBase64Url(recipients));
    }

    @Test
    void shouldProduceDifferentAadWhenRecipientsChanged() {
        List<RecipientEntry> original = List.of(
                new RecipientEntry(new KidRef("kid-x", null), null, null, "enc-key-1"));
        List<RecipientEntry> tampered = List.of(
                new RecipientEntry(new KidRef("kid-x", null), null, null, "enc-key-2"));

        String originalAad = aadService.computeAadBase64Url(original);
        String tamperedAad = aadService.computeAadBase64Url(tampered);

        assertNotEquals(originalAad, tamperedAad);
    }

    @Test
    void shouldProduceSameAadWhenRecipientsFieldOrderDiffers() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String recipientsJsonA = """
                [
                  {
                    "kid": {"x25519":"kid-r1"},
                    "encrypted_key":"enc-r1"
                  }
                ]
                """;
        String recipientsJsonB = """
                [
                  {
                    "encrypted_key":"enc-r1",
                    "kid": {"x25519":"kid-r1"}
                  }
                ]
                """;

        String aadA = aadService.computeAadBase64Url(objectMapper.readTree(recipientsJsonA));
        String aadB = aadService.computeAadBase64Url(objectMapper.readTree(recipientsJsonB));

        assertEquals(aadA, aadB);
    }

    @Test
    void shouldDistinguishAbsentAndNullInRecipientsNodeAad() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String recipientsAbsent = """
                [
                  {
                    "encrypted_key":"enc-r1"
                  }
                ]
                """;
        String recipientsNull = """
                [
                  {
                    "encrypted_key":"enc-r1",
                    "rid":null
                  }
                ]
                """;

        String aadAbsent = aadService.computeAadBase64Url(objectMapper.readTree(recipientsAbsent));
        String aadNull = aadService.computeAadBase64Url(objectMapper.readTree(recipientsNull));

        assertNotEquals(aadAbsent, aadNull);
    }
}
