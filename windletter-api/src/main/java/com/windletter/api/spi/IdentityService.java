package com.windletter.api.spi;

import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import java.util.Optional;

/**
 * 身份解析接口。
 * <p>
 * 同时服务发送侧（签名身份材料）与接收侧（验签公钥、发送方展示信息）。
 */
public interface IdentityService {

    /**
     * 解析发送侧签名身份材料。
     */
    Optional<SigningIdentityMaterial> resolveSigningIdentity(SigningIdentityRef signingIdentityRef);

    /**
     * 通过 signing kid 查询验签公钥。
     */
    Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String signingKid);

    /**
     * 通过 signing kid 查询发送方展示身份。
     */
    Optional<SenderIdentity> resolveSenderBySigningKid(String signingKid);
}
