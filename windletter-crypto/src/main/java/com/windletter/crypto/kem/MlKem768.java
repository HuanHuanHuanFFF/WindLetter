package com.windletter.crypto.kem;

import com.windletter.crypto.CryptoException;

/**
 * ML-KEM-768 (Kyber-768) placeholder.
 * ML-KEM-768（Kyber-768）实现占位。
 */
public class MlKem768 {

    public KemEncapsulationResult encapsulate(byte[] publicKey) {
        throw new CryptoException("ML-KEM-768 encapsulation not yet implemented");
    }

    public byte[] decapsulate(byte[] privateKey, byte[] encapsulated) {
        throw new CryptoException("ML-KEM-768 decapsulation not yet implemented");
    }
}
