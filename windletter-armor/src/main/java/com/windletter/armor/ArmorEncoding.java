package com.windletter.armor;

/**
 * Supported armor encoding identifiers.
 * 支持的装甲编码标识。
 */
public enum ArmorEncoding {
    BASE64URL("base64url"),
    WINDBASE1024F("windbase1024f");

    private final String jsonValue;

    ArmorEncoding(String jsonValue) {
        this.jsonValue = jsonValue;
    }

    public String jsonValue() {
        return jsonValue;
    }
}
