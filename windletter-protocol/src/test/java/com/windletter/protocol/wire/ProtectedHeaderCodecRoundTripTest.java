package com.windletter.protocol.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import org.junit.jupiter.api.Test;

class ProtectedHeaderCodecRoundTripTest {

    private final ProtectedHeaderCodec codec = new DefaultProtectedHeaderCodec();

    @Test
    void shouldRoundTripByEncodeDecode() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe",
                "wind+jws",
                "1.0",
                "public",
                "A256GCM",
                "X25519ML-KEM-768",
                new KidRef("kid-ecc-s1", "kid-pq-s1"),
                new EpkRef("OKP", "X25519", "epk-x"));

        String encoded = codec.encode(header);
        ProtectedHeader decoded = codec.decode(encoded);

        assertEquals(header, decoded);
    }

    @Test
    void shouldRejectMalformedBase64Payload() {
        ProtocolException ex = assertThrows(ProtocolException.class, () -> codec.decode("@@@"));
        assertEquals(ErrorCode.MALFORMED_WIRE, ex.errorCode());
    }
}
