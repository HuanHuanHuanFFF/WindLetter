package com.windletter.core.encoding;

/**
 * Unified encoding entry points for Base64URL and the upcoming WindBase1024F.
 * Base64URL 及未来 WindBase1024F 的统一编码接口。
 */
public interface WindEncoding {
    String base64UrlEncode(byte[] data);

    byte[] base64UrlDecode(String text);

    /**
        * Placeholder for WindBase1024F; to be implemented in a later iteration.
        */
    String windBase1024fEncode(byte[] data);

    /**
        * Placeholder for WindBase1024F; to be implemented in a later iteration.
        */
    byte[] windBase1024fDecode(String text);
}
