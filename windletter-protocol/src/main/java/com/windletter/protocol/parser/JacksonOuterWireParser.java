package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.protocol.wire.JacksonOuterWireCodec;
import com.windletter.protocol.wire.OuterWireCodec;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ParsedOuterWire;

/**
 * Backward-compatible parser facade delegating to {@link OuterWireCodec}.
 */
public final class JacksonOuterWireParser implements OuterWireParser {

    private final OuterWireCodec outerWireCodec;

    /**
     * Create parser with default Jackson codec.
     */
    public JacksonOuterWireParser() {
        this(new JacksonOuterWireCodec());
    }

    /**
     * Create parser with caller-provided ObjectMapper.
     */
    public JacksonOuterWireParser(ObjectMapper objectMapper) {
        this(new JacksonOuterWireCodec(objectMapper));
    }

    /**
     * Create parser with caller-provided codec.
     */
    public JacksonOuterWireParser(OuterWireCodec outerWireCodec) {
        if (outerWireCodec == null) {
            throw new IllegalArgumentException("outerWireCodec must not be null");
        }
        this.outerWireCodec = outerWireCodec;
    }

    /**
     * Delegate parse to configured outer wire codec.
     */
    @Override
    public OuterWireMessage parse(String wireJson) {
        return outerWireCodec.parse(wireJson);
    }

    /**
     * Delegate raw parse to configured outer wire codec.
     */
    @Override
    public ParsedOuterWire parseWithRaw(String wireJson) {
        return outerWireCodec.parseWithRaw(wireJson);
    }
}
