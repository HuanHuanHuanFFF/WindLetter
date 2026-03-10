package com.windletter.protocol.wire;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Parsed outer wire with preserved raw recipients JSON node for AAD recomputation.
 */
public record ParsedOuterWire(OuterWireMessage wire, JsonNode recipientsNode) {

    public ParsedOuterWire {
        if (recipientsNode != null) {
            recipientsNode = recipientsNode.deepCopy();
        }
    }
}
