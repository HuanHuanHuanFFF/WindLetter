package com.windletter.api;

import com.windletter.crypto.keys.EccKeyPair;
import com.windletter.crypto.keys.PqcKemKeyPair;

/**
 * Lookup interface for recipient private keys by kid or encoding.
 * 按 kid 或编码查找收件人私钥的接口。
 */
public interface RecipientKeyStore {
    EccKeyPair findEccKeyByKid(String kid);

    PqcKemKeyPair findPqcKeyByKid(String kid);
}
