package com.windletter.crypto.keys;

import java.util.Arrays;

/**
 * PQC KEM key pair (ML-KEM-768).
 * PQC KEM（ML-KEM-768）密钥对。
 */
public final class PqcKemKeyPair {
    private final String kid;
    private final byte[] publicKey;
    private final byte[] privateKey;

    public PqcKemKeyPair(String kid, byte[] publicKey, byte[] privateKey) {
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
