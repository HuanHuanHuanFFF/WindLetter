package com.windletter.api.spi;

import java.util.Arrays;
import java.util.Map;

/**
 * 验签公钥材料。
 *
 * @param signingKid 签名 kid
 * @param ed25519PublicKey Ed25519 公钥
 * @param metadata 可扩展元数据
 */
public record VerificationKeyMaterial(
    String signingKid,
    byte[] ed25519PublicKey,
    Map<String, String> metadata
) {

    public VerificationKeyMaterial {
        signingKid = SpiChecks.requireNonBlank(signingKid, "signingKid");
        if (ed25519PublicKey == null || ed25519PublicKey.length == 0) {
            throw new IllegalArgumentException("ed25519PublicKey must not be empty");
        }
        ed25519PublicKey = Arrays.copyOf(ed25519PublicKey, ed25519PublicKey.length);
        metadata = SpiChecks.copyMap(metadata);
    }

    @Override
    public byte[] ed25519PublicKey() {
        // 返回副本，避免外部修改内部公钥数组。
        return Arrays.copyOf(ed25519PublicKey, ed25519PublicKey.length);
    }
}
