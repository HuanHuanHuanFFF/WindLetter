package com.windletter.api;

/**
 * High-level decrypt-and-verify entry.
 * 高层解密+验签入口。
 */
public class WindLetterReceiver {

    public DecryptResult decryptAndVerify(String jweOrArmorText, RecipientKeyStore keyStore) {
        throw new UnsupportedOperationException("Decrypt-and-verify not yet implemented");
    }
}
