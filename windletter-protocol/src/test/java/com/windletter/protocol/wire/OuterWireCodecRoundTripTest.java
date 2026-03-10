package com.windletter.protocol.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class OuterWireCodecRoundTripTest {

    private final OuterWireCodec codec = new JacksonOuterWireCodec();

    @Test
    void shouldRoundTripByParseSerializeParse() {
        String wireJson = """
                {
                  "protected": "eyJ0eXAiOiJ3aW5kK2p3ZSIsImN0eSI6IndpbmQrait3cyIsInZlciI6IjEuMCIsIndpbmRfbW9kZSI6InB1YmxpYyIsImVuYyI6IkEyNTZHQ00iLCJrZXlfYWxnIjoiWDI1NTE5In0",
                  "aad": "W3siZW5jcnlwdGVkX2tleSI6ImVuYzEifV0",
                  "recipients": [
                    {
                      "kid": {
                        "x25519": "kid-ecc-r1"
                      },
                      "encrypted_key": "enc1"
                    }
                  ],
                  "iv": "aXY",
                  "ciphertext": "Y3Q",
                  "tag": "dGFn"
                }
                """;

        OuterWireMessage first = codec.parse(wireJson);
        String serialized = codec.serialize(first);
        OuterWireMessage second = codec.parse(serialized);

        assertEquals(first, second);
    }
}
