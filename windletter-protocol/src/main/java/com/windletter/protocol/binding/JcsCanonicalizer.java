package com.windletter.protocol.binding;

/**
 * RFC 8785 JSON canonicalization abstraction.
 */
public interface JcsCanonicalizer {

    byte[] canonicalize(Object value);
}
