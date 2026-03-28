package com.windletter.protocol.parser;

import com.windletter.protocol.wire.OuterData;

/**
 * Outer wire parser entry point.
 */
public interface OuterWireParser {

    /**
     * Parse and strictly validate outer wire JSON.
     *
     * @param wireJson outer wire JSON string
     * @return parsed branch-specific outer message
     */
    OuterData parse(String wireJson);
}
