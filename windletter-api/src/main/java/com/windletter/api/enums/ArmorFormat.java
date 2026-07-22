package com.windletter.api.enums;

/**
 * Text armor format.
 * <p>
 * Notes:
 * <ul>
 *   <li>{@code NONE} means no text armor is used; only wire JSON is transmitted.</li>
 *   <li>{@code BASE64_PEM}/{@code WIND_BASE_1024F_V1} represent armor string encoding schemes.</li>
 *   <li>{@code BINARY} represents a binary transport channel (not carried by armor string).</li>
 * </ul>
 */
public enum ArmorFormat {
    /** No text armor. */
    NONE,
    /** RFC 4648 standard Base64 in a PEM-style text envelope. */
    BASE64_PEM,
    /** WindBase1024F v1 text armor. */
    WIND_BASE_1024F_V1,
    /** Binary armor (for example file/stream channels). */
    BINARY
}
