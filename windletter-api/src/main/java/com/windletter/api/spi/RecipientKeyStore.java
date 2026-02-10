package com.windletter.api.spi;

import com.windletter.api.model.RecipientIdentityRef;
import java.util.List;
import java.util.Optional;

/**
 * 接收侧密钥查询接口。
 * <p>
 * findPrimary 用于快速路径；findAll 用于多键轮换或回退尝试。
 */
public interface RecipientKeyStore {

    /**
     * 查询首选解密密钥。
     */
    Optional<DecryptionKeyMaterial> findPrimary(RecipientIdentityRef recipientIdentityRef);

    /**
     * 查询候选解密密钥列表。
     */
    List<DecryptionKeyMaterial> findAll(RecipientIdentityRef recipientIdentityRef);
}
