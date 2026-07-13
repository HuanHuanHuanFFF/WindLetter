package com.windletter.protocol.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.WindLetter;

/**
 * Serializes the typed outer wire projection without recomputing protected or AAD values.
 */
public final class JacksonOuterWireWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public String write(WindLetter letter) {
        try {
            return MAPPER.writeValueAsString(OuterJsonMapper.toOuterJson(letter));
        } catch (JsonProcessingException | RuntimeException e) {
            throw new ProtocolException(ErrorCode.INTERNAL_ERROR, "failed to serialize outer wire", e);
        }
    }
}
