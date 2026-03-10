package com.windletter.protocol.wire;

import java.util.List;

/**
 * Outer wire message in transport form.
 */
public record OuterWireMessage(
    String protectedB64,
    String aadB64,
    List<RecipientEntry> recipients,
    String ivB64,
    String ciphertextB64,
    String tagB64
) {
    public OuterWireMessage {
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        recipients = List.copyOf(recipients);
    }
}
