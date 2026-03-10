package com.windletter.protocol.wire;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Recipient entry mapped from outer wire recipients array.
 */
public record RecipientEntry(
        KidRef kid,
        String rid,
        String ek,
        @JsonProperty("encrypted_key") String encryptedKey) {
}
