package com.windletter.protocol;

/**
 * Recipient visibility mode.
 * 收件人可见性模式。
 */
public enum WindMode {
    PUBLIC("public"),
    OBFUSCATION("obfuscation");

    private final String jsonValue;

    WindMode(String jsonValue) {
        this.jsonValue = jsonValue;
    }

    public String jsonValue() {
        return jsonValue;
    }
}
