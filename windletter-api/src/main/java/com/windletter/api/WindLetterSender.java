package com.windletter.api;

import com.windletter.protocol.RecipientPublicInfo;
import com.windletter.protocol.WindMode;
import com.windletter.protocol.payload.WindPayload;

import java.util.List;

/**
 * High-level encrypt-and-sign entry.
 * 高层加密+签名入口。
 */
public class WindLetterSender {

    public EncryptedMessage encryptAndSign(WindPayload payload,
                                           WindIdentity sender,
                                           List<RecipientPublicInfo> recipients,
                                           WindMode mode) {
        throw new UnsupportedOperationException("Encrypt-and-sign not yet implemented");
    }
}
