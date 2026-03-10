package com.windletter.protocol.wire;

/**
 * Symmetric codec for outer wire JSON.
 */
public interface OuterWireCodec {

    /**
     * Parse outer wire JSON into typed message object.
     */
    OuterWireMessage parse(String wireJson);

    /**
     * Parse outer wire JSON and preserve raw recipients node for AAD recomputation.
     */
    ParsedOuterWire parseWithRaw(String wireJson);

    /**
     * Serialize typed outer wire message into JSON.
     */
    String serialize(OuterWireMessage wire);
}
