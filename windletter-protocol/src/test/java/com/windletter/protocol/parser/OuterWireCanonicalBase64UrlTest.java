package com.windletter.protocol.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OuterWireCanonicalBase64UrlTest {

    private static final String BASE64_URL_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private final OuterWireParser parser = new JacksonOuterWireParser();

    @Test
    void rejectsNonCanonicalProtectedEncoding() {
        ObjectNode outer = validOuter();
        String protectedJson = new String(
                Base64.getUrlDecoder().decode(outer.get("protected").asText()),
                StandardCharsets.UTF_8
        );
        String canonical = b64(protectedJson.getBytes(StandardCharsets.UTF_8));
        while (canonical.length() % 4 == 0) {
            protectedJson += " ";
            canonical = b64(protectedJson.getBytes(StandardCharsets.UTF_8));
        }
        outer.put("protected", nonCanonicalAlias(canonical));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalAadEncoding() {
        ObjectNode outer = validOuter();
        outer.put("aad", nonCanonicalAlias(b64(bytes(1, 11))));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalIvEncodingBeforeLengthValidation() {
        ObjectNode outer = validOuter();
        outer.put("iv", nonCanonicalAlias(b64(bytes(13, 12))));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalCiphertextEncoding() {
        ObjectNode outer = validOuter();
        outer.put("ciphertext", nonCanonicalAlias(b64(bytes(1, 13))));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalTagEncoding() {
        ObjectNode outer = validOuter();
        outer.put("tag", nonCanonicalAlias(b64(bytes(16, 14))));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalKidEncoding() {
        ObjectNode outer = validOuter();
        ObjectNode header = decodeProtected(outer);
        ObjectNode kid = (ObjectNode) header.get("kid");
        kid.put("x25519", nonCanonicalAlias(b64(bytes(32, 15))));
        outer.put("protected", b64(toJson(header).getBytes(StandardCharsets.UTF_8)));

        assertMalformed(outer);
    }

    @Test
    void rejectsNonCanonicalEncryptedKeyEncoding() {
        ObjectNode outer = validOuter();
        ObjectNode recipient = (ObjectNode) outer.withArray("recipients").get(0);
        recipient.put("encrypted_key", nonCanonicalAlias(b64(bytes(40, 16))));

        assertMalformed(outer);
    }

    private void assertMalformed(ObjectNode outer) {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> parser.parse(toJson(outer)));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }

    private static ObjectNode validOuter() {
        ObjectNode header = MAPPER.createObjectNode()
                .put("typ", "wind+jwe")
                .put("cty", "wind+inner")
                .put("ver", "1.0")
                .put("wind_mode", "public")
                .put("enc", "A256GCM")
                .put("key_alg", "X25519");
        header.set("kid", MAPPER.createObjectNode().put("x25519", b64(bytes(32, 1))));

        ObjectNode recipient = MAPPER.createObjectNode();
        recipient.set("kid", MAPPER.createObjectNode().put("x25519", b64(bytes(32, 2))));
        recipient.put("encrypted_key", b64(bytes(40, 3)));

        ArrayNode recipients = MAPPER.createArrayNode().add(recipient);
        ObjectNode outer = MAPPER.createObjectNode();
        outer.put("protected", b64(toJson(header).getBytes(StandardCharsets.UTF_8)));
        outer.put("aad", b64(bytes(1, 4)));
        outer.set("recipients", recipients);
        outer.put("iv", b64(bytes(12, 5)));
        outer.put("ciphertext", b64(bytes(24, 6)));
        outer.put("tag", b64(bytes(16, 7)));
        return outer;
    }

    private static ObjectNode decodeProtected(ObjectNode outer) {
        try {
            return (ObjectNode) MAPPER.readTree(Base64.getUrlDecoder().decode(outer.get("protected").asText()));
        } catch (IOException e) {
            throw new IllegalStateException("failed to decode protected test fixture", e);
        }
    }

    private static String nonCanonicalAlias(String canonical) {
        int remainder = canonical.length() % 4;
        if (remainder != 2 && remainder != 3) {
            throw new IllegalArgumentException("fixture must have unused trailing Base64URL bits");
        }
        int lastIndex = canonical.length() - 1;
        int alphabetIndex = BASE64_URL_ALPHABET.indexOf(canonical.charAt(lastIndex));
        if (alphabetIndex < 0) {
            throw new IllegalArgumentException("fixture is not Base64URL");
        }
        return canonical.substring(0, lastIndex) + BASE64_URL_ALPHABET.charAt(alphabetIndex + 1);
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

    private static String toJson(com.fasterxml.jackson.databind.JsonNode node) {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to build test json", e);
        }
    }
}
