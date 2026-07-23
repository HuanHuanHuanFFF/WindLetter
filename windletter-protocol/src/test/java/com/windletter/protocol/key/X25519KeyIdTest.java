package com.windletter.protocol.key;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.protocol.codec.JcsCanonicalizer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class X25519KeyIdTest {

    private static final byte[] PUBLIC_KEY = HexFormat.of().parseHex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    private static final String EXPECTED_X =
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
    private static final String EXPECTED_JWK =
            "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}";
    private static final String EXPECTED_KID =
            "u809Vppx5ixWMOohxWr2aM3m5bD0LQ67g_GPmubQus4";

    @Test
    void derivesRfc7638ThumbprintFromExactX25519Jwk() {
        ObjectNode expectedJwk = JsonNodeFactory.instance.objectNode();
        expectedJwk.put("x", EXPECTED_X);
        expectedJwk.put("kty", "OKP");
        expectedJwk.put("crv", "X25519");

        assertEquals(
                EXPECTED_JWK,
                new String(JcsCanonicalizer.canonicalize(expectedJwk), StandardCharsets.UTF_8)
        );
        assertEquals(EXPECTED_KID, X25519KeyId.derive(PUBLIC_KEY));
    }

    @Test
    void rejectsNullAndNon32BytePublicKeys() {
        assertThrows(IllegalArgumentException.class, () -> X25519KeyId.derive(null));
        assertThrows(IllegalArgumentException.class, () -> X25519KeyId.derive(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> X25519KeyId.derive(new byte[33]));
    }
}
