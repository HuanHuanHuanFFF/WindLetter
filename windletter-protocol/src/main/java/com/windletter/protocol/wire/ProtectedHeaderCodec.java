package com.windletter.protocol.wire;

/**
 * Symmetric codec for protected header Base64URL payload.
 */
public interface ProtectedHeaderCodec {

    /**
     * Decode Base64URL protected header JSON.
     */
    ProtectedHeader decode(String protectedB64);

    /**
     * Encode protected header JSON into Base64URL form.
     */
    String encode(ProtectedHeader header);
}
