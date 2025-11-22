package com.windletter.protocol.jcs;

/**
 * RFC 8785 JSON Canonicalization Scheme interface.
 * RFC 8785 的 JSON 规范化接口。
 */
public interface JsonCanonicalizer {
    /**
     * Canonicalize arbitrary JSON input into normalized string.
     */
    String canonicalize(String jsonText);
}
