package com.windletter.protocol.codec;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.windletter.protocol.ProtocolLimits;

/**
 * Factory for JSON mappers that reject ambiguous or unbounded wire input.
 */
public final class StrictJson {

    private StrictJson() {
    }

    public static ObjectMapper newMapper() {
        StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxNestingDepth(ProtocolLimits.MAX_JSON_DEPTH)
                .maxDocumentLength(ProtocolLimits.MAX_WIRE_UTF8_BYTES)
                .maxStringLength(ProtocolLimits.MAX_WIRE_UTF8_BYTES)
                .build();
        JsonFactory factory = JsonFactory.builder()
                .streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .build();
        return JsonMapper.builder(factory)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
    }
}
