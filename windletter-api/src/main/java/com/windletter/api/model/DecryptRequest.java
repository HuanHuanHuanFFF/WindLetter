package com.windletter.api.model;

import com.windletter.api.enums.VerificationPolicy;

/**
 * 接收侧解密请求。
 *
 * @param wireJson 原始 wire JSON（与 armor 至少二选一）
 * @param armor 文本封装（与 wireJson 至少二选一）
 * @param myIdentity 本地接收身份
 * @param verificationPolicy 验签策略，null 时默认 AUTO_BY_CTY
 */
public record DecryptRequest(
    String wireJson,
    String armor,
    RecipientIdentityRef myIdentity,
    VerificationPolicy verificationPolicy
) {

    public DecryptRequest {
        // 保证调用方至少提供一种输入表示。
        if (ModelChecks.isBlank(wireJson) && ModelChecks.isBlank(armor)) {
            throw new IllegalArgumentException("wireJson or armor must be provided");
        }
        myIdentity = ModelChecks.requireNonNull(myIdentity, "myIdentity");
        verificationPolicy = verificationPolicy == null
            ? VerificationPolicy.AUTO_BY_CTY
            : verificationPolicy;
    }
}
