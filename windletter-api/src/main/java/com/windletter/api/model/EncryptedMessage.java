package com.windletter.api.model;

/**
 * 对外稳定密文载体。
 *
 * @param wireJson 标准 wire JSON（必填）
 * @param armor 可选文本封装表示
 */
public record EncryptedMessage(String wireJson, String armor) {

    public EncryptedMessage {
        wireJson = ModelChecks.requireNonBlank(wireJson, "wireJson");
    }
}
