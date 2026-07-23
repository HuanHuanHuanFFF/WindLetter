package com.windletter.protocol.key;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.protocol.codec.JcsCanonicalizer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Ed25519KeyIdTest {

    private static final byte[] PUBLIC_KEY = HexFormat.of().parseHex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    private static final String EXPECTED_X =
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    private static final String EXPECTED_JWK =
            "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
    private static final String EXPECTED_KID =
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    @Test
    void derivesRfc7638ThumbprintFromExactEd25519Jwk() {
        ObjectNode expectedJwk = JsonNodeFactory.instance.objectNode();
        expectedJwk.put("x", EXPECTED_X);
        expectedJwk.put("kty", "OKP");
        expectedJwk.put("crv", "Ed25519");

        assertEquals(
                EXPECTED_JWK,
                new String(JcsCanonicalizer.canonicalize(expectedJwk), StandardCharsets.UTF_8)
        );
        assertEquals(EXPECTED_KID, Ed25519KeyId.derive(PUBLIC_KEY));
    }

    @Test
    void rejectsNullAndNon32BytePublicKeys() {
        assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(null));
        assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Ed25519KeyId.derive(new byte[33]));
    }
}
