package com.windletter.api.model;

/**
 * 发送侧签名身份引用。
 *
 * @param identityId 业务身份 ID
 * @param signingKid 可选签名 kid 提示
 */
public record SigningIdentityRef(String identityId, String signingKid) {

    public SigningIdentityRef {
        identityId = ModelChecks.requireNonBlank(identityId, "identityId");
    }
}
