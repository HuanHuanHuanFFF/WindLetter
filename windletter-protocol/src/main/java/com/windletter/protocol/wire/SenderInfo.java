package com.windletter.protocol.wire;

/**
 * Sender information from protected header, selected by wind mode.
 */
public sealed interface SenderInfo permits PublicSenderInfo, ObfuscationSenderInfo {
}

