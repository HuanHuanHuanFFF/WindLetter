package com.windletter.crypto.kem;

/**
 * Result of KEM encapsulation: shared secret + encapsulated key blob.
 * KEM 封装结果：共享密钥与封装密文。
 */
public class KemEncapsulationResult {
    private final byte[] sharedSecret;
    private final byte[] encapsulated;

    public KemEncapsulationResult(byte[] sharedSecret, byte[] encapsulated) {
        this.sharedSecret = sharedSecret;
        this.encapsulated = encapsulated;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public byte[] getEncapsulated() {
        return encapsulated;
    }
}
