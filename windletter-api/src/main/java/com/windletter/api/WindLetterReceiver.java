package com.windletter.api;

import com.windletter.api.model.DecryptRequest;
import com.windletter.api.model.DecryptResult;

/**
 * 接收侧门面接口。
 * <p>
 * 该接口只定义输入输出与结果语义，具体验签/解密流程由实现层提供。
 */
public interface WindLetterReceiver {

    /**
     * 解密消息，验签策略由 {@code DecryptRequest.verificationPolicy} 决定。
     */
    DecryptResult decrypt(DecryptRequest req);

    /**
     * 解密并要求执行验签语义（实现可比 {@link #decrypt(DecryptRequest)} 更严格）。
     */
    DecryptResult decryptAndVerify(DecryptRequest req);
}
