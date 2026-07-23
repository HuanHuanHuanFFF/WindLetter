package com.windletter.protocol.key;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * RFC 7638 JWK thumbprint for an X25519 public key.
 */
public final class X25519KeyId {

    private static final int PUBLIC_KEY_LENGTH = 32;

    private X25519KeyId() {
    }

    public static String derive(byte[] publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey must not be null");
        }
        if (publicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey must contain exactly 32 bytes");
        }

        ObjectNode jwk = JsonNodeFactory.instance.objectNode();
        jwk.put("crv", "X25519");
        jwk.put("kty", "OKP");
        jwk.put("x", Base64Url.encode(publicKey));
        return Base64Url.encode(sha256(JcsCanonicalizer.canonicalize(jwk)));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
