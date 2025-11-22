package com.windletter.core;

/**
 * Fixed sizes and literal values mandated by the specification.
 * 规范规定的固定长度和字面量。
 */
public final class WindConstants {
    private WindConstants() {
    }

    public static final int CEK_SIZE_BYTES = 32;
    public static final int IV_SIZE_BYTES = 12;
    public static final String DEFAULT_VERSION = "1.0";
    public static final String DEFAULT_CONTENT_TYPE = WindAlgorithms.TYP_JWS;
    public static final String WIND_ID_INFO = "wind+jwe/iv/v1";
}
