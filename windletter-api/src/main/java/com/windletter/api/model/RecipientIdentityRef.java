package com.windletter.api.model;

/**
 * 接收侧身份引用。
 *
 * @param recipientId 接收方身份 ID
 * @param keySelector 可选键选择器（用于多键轮换场景）
 */
public record RecipientIdentityRef(String recipientId, String keySelector) {

    public RecipientIdentityRef {
        recipientId = ModelChecks.requireNonBlank(recipientId, "recipientId");
    }
}
