package com.windletter.protocol.wire;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.List;

/**
 * Outer wire transport object for Wind Letter v1.0.
 */
@JsonPropertyOrder({"protected", "aad", "recipients", "iv", "ciphertext", "tag"})
public record OuterWireMessage(
        @JsonProperty("protected") String protectedB64,
        @JsonProperty("aad") String aadB64,
        List<RecipientEntry> recipients,
        @JsonProperty("iv") String ivB64,
        @JsonProperty("ciphertext") String ciphertextB64,
        @JsonProperty("tag") String tagB64) {

    public OuterWireMessage {
        if (recipients != null) {
            recipients = List.copyOf(recipients);
        }
    }
}
