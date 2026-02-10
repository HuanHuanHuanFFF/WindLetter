package com.windletter.api;

import com.windletter.api.model.EncryptAndSignRequest;
import com.windletter.api.model.EncryptRequest;
import com.windletter.api.model.EncryptedMessage;

/**
 * 发送侧门面接口。
 * <p>
 * 该接口只定义调用契约，不包含协议编排或密码实现。
 */
public interface WindLetterSender {

    /**
     * 仅加密，不做签名。
     */
    EncryptedMessage encrypt(EncryptRequest req);

    /**
     * 加密并附加签名。
     */
    EncryptedMessage encryptAndSign(EncryptAndSignRequest req);
}
