package com.windletter.api.model;

import java.util.Map;

/**
 * 验签后可返回的发送方身份信息。
 *
 * @param senderId 发送方身份 ID
 * @param signingKid 签名 kid
 * @param attributes 可扩展元数据
 */
public record SenderIdentity(String senderId, String signingKid, Map<String, String> attributes) {

    public SenderIdentity {
        senderId = ModelChecks.requireNonBlank(senderId, "senderId");
        signingKid = ModelChecks.requireNonBlank(signingKid, "signingKid");
        attributes = ModelChecks.copyMap(attributes);
    }
}
