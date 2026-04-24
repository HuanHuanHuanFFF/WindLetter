package com.windletter.protocol.parser;

import com.windletter.protocol.wire.WindLetter;

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
    WindLetter parse(String wireJson);
}
