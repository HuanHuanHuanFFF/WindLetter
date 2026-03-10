package com.windletter.protocol.parser;

import com.windletter.protocol.wire.OuterWireMessage;

/**
 * Parser for outer wire transport JSON.
 */
public interface OuterWireParser {

    OuterWireMessage parse(String wireJson);
}
