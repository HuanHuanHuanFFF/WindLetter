package com.windletter.core.encoding;

/**
 * Default encoding implementation. WindBase1024F is temporarily mapped to Base64URL
 * until the dedicated alphabet is delivered.
 * 默认编码实现；WindBase1024F 先临时使用 Base64URL 代替。
 */
public class DefaultWindEncoding implements WindEncoding {
    @Override
    public String base64UrlEncode(byte[] data) {
        return Base64Url.encode(data);
    }

    @Override
    public byte[] base64UrlDecode(String text) {
        return Base64Url.decode(text);
    }

    @Override
    public String windBase1024fEncode(byte[] data) {
        // TODO: replace with real WindBase1024F encoding.
        return Base64Url.encode(data);
    }

    @Override
    public byte[] windBase1024fDecode(String text) {
        // TODO: replace with real WindBase1024F decoding.
        return Base64Url.decode(text);
    }
}
