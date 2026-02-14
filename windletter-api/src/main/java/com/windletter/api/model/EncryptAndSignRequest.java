package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;
import java.util.List;
import java.util.Map;

/**
 * 发送侧加密+签名请求。
 *
 * @param mode 传输模式
 * @param keyAlgProfile 密钥算法 profile
 * @param armorFormat 输出 armor 格式，null 时默认 NONE
 * @param payload 业务载荷
 * @param recipients 收件人列表（非空）
 * @param customHeaders 可选自定义头扩展（放在 payload.meta.ext 里）
 * @param senderSigningIdentity 签名身份引用（必填）
 */
public record EncryptAndSignRequest(
    WindMode mode,
    KeyAlgProfile keyAlgProfile,
    ArmorFormat armorFormat,
    Payload payload,
    List<RecipientRef> recipients,
    Map<String, Object> customHeaders,
    SigningIdentityRef senderSigningIdentity
) {

    public EncryptAndSignRequest {
        mode = ModelChecks.requireNonNull(mode, "mode");
        keyAlgProfile = ModelChecks.requireNonNull(keyAlgProfile, "keyAlgProfile");
        armorFormat = armorFormat == null ? ArmorFormat.NONE : armorFormat;
        payload = ModelChecks.requireNonNull(payload, "payload");
        recipients = ModelChecks.copyNonEmptyList(recipients, "recipients");
        customHeaders = ModelChecks.copyMap(customHeaders);
        senderSigningIdentity = ModelChecks.requireNonNull(senderSigningIdentity, "senderSigningIdentity");
    }
}
