package com.windletter.protocol.parser;

import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ParsedOuterWire;

/**
 * Parser for outer wire JSON payload.
 */
public interface OuterWireParser {

    /**
     * Parse wire JSON into typed outer message.
     */
    OuterWireMessage parse(String wireJson);

    /**
     * Parse wire JSON with raw recipients node preserved for canonical AAD validation.
     */
    ParsedOuterWire parseWithRaw(String wireJson);
}
