package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * 发送侧签名身份材料。
 *
 * @param identityId 业务身份 ID
 * @param signingKid 签名 kid
 * @param ed25519PrivateKey Ed25519 私钥
 * @param metadata 可扩展元数据
 */
public record SigningIdentityMaterial(
    String identityId,
    String signingKid,
    byte[] ed25519PrivateKey,
    Map<String, String> metadata
) {

    public SigningIdentityMaterial {
        identityId = SpiChecks.requireNonBlank(identityId, "identityId");
        signingKid = SpiChecks.requireNonBlank(signingKid, "signingKid");
        if (ed25519PrivateKey == null || ed25519PrivateKey.length == 0) {
            throw new IllegalArgumentException("ed25519PrivateKey must not be empty");
        }
        ed25519PrivateKey = Arrays.copyOf(ed25519PrivateKey, ed25519PrivateKey.length);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] ed25519PrivateKey() {
        // 返回副本，避免外部修改内部密钥数组。
        return Arrays.copyOf(ed25519PrivateKey, ed25519PrivateKey.length);
    }
}
