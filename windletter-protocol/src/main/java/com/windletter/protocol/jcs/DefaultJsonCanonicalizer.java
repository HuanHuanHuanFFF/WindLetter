package com.windletter.protocol.jcs;

/**
 * Default implementation for RFC8785 canonicalization.
 * RFC8785 规范化的默认实现。
 */
public class DefaultJsonCanonicalizer implements JsonCanonicalizer {
    @Override
    public String canonicalize(String jsonText) {
        try {
            org.erdtman.jcs.JsonCanonicalizer canonicalizer = new org.erdtman.jcs.JsonCanonicalizer(jsonText);
            return canonicalizer.getEncodedString();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to canonicalize JSON", e);
        }
    }
}
