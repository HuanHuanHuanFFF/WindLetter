package com.windletter.protocol.wire;

/**
 * Recipient entry in outer wire transport message.
 */
public record RecipientEntry(
    KidRef kid,
    String rid,
    String ek,
    String encryptedKey
) {
}
