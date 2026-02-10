package com.windletter.api.model;

import java.util.Map;

/**
 * 发送侧收件人引用。
 *
 * @param recipientId 业务层收件人标识
 * @param x25519Kid X25519 公钥 kid（可选）
 * @param mlkem768Kid ML-KEM-768 公钥 kid（可选）
 * @param attributes 可扩展附加信息
 */
public record RecipientRef(
    String recipientId,
    String x25519Kid,
    String mlkem768Kid,
    Map<String, String> attributes
) {

    public RecipientRef {
        recipientId = ModelChecks.requireNonBlank(recipientId, "recipientId");
        // 至少提供一种可用于密钥解析的标识。
        if (ModelChecks.isBlank(x25519Kid) && ModelChecks.isBlank(mlkem768Kid)) {
            throw new IllegalArgumentException("at least one recipient key reference must be provided");
        }
        attributes = ModelChecks.copyMap(attributes);
    }
}
