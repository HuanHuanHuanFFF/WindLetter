package com.windletter.protocol.wire;

/**
 * Recipient entry selected by wind mode.
 */
public sealed interface RecipientEntry permits PublicRecipient, ObfuscationRecipient {

    byte[] encryptedKey();
}
