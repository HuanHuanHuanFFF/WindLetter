package com.windletter.protocol.wire;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outer protected header mapped from Base64URL-decoded JSON.
 */
public record ProtectedHeader(
        String typ,
        String cty,
        String ver,
        @JsonProperty("wind_mode") String windMode,
        String enc,
        @JsonProperty("key_alg") String keyAlg,
        KidRef kid,
        EpkRef epk) {
}
