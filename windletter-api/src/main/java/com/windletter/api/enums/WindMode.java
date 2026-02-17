package com.windletter.api.enums;

/**
 * Transport mode.
 */
public enum WindMode {
    /** Public mode, recipient identifiers are visible. */
    PUBLIC,
    /** Obfuscation mode, uses rid and padding to reduce relationship exposure. */
    OBFUSCATION
}
