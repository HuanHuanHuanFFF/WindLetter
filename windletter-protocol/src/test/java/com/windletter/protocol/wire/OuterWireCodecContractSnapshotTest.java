package com.windletter.protocol.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class OuterWireCodecContractSnapshotTest {

    private final OuterWireCodec codec = new JacksonOuterWireCodec();

    @Test
    void shouldMatchV1MinimalSerializationSnapshot() {
        OuterWireMessage wire = new OuterWireMessage(
                "cHJvdGVjdGVk",
                "YWFk",
                List.of(new RecipientEntry(
                        new KidRef("kid-ecc-r1", "kid-pq-r1"),
                        "rid-r1",
                        "ek-r1",
                        "enc-r1")),
                "aXY",
                "Y3Q",
                "dGFn");

        String serialized = codec.serialize(wire);
        String expected = "{\"protected\":\"cHJvdGVjdGVk\",\"aad\":\"YWFk\",\"recipients\":[{\"kid\":{\"x25519\":\"kid-ecc-r1\",\"mlkem768\":\"kid-pq-r1\"},\"rid\":\"rid-r1\",\"ek\":\"ek-r1\",\"encrypted_key\":\"enc-r1\"}],\"iv\":\"aXY\",\"ciphertext\":\"Y3Q\",\"tag\":\"dGFn\"}";

        assertEquals(expected, serialized);
    }
}
