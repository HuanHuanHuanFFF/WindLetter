package com.windletter.crypto.keys;

import java.util.Arrays;

/**
 * Ed25519 or X25519 key pair identified by kid.
 * 带 kid 的 Ed25519/X25519 密钥对。
 */
public final class EccKeyPair {
    private final String kid;
    private final byte[] publicKey;
    private final byte[] privateKey;

    public EccKeyPair(String kid, byte[] publicKey, byte[] privateKey) {
        this.kid = kid;
        this.publicKey = Arrays.copyOf(publicKey, publicKey.length);
        this.privateKey = Arrays.copyOf(privateKey, privateKey.length);
    }

    public String getKid() {
        return kid;
    }

    public byte[] getPublicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    public byte[] getPrivateKey() {
        return Arrays.copyOf(privateKey, privateKey.length);
    }
}
