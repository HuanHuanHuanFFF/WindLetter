package com.windletter.crypto.kem;

import com.windletter.crypto.CryptoException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import java.security.SecureRandom;

/**
 * ML-KEM-768 (Kyber-768) placeholder.
 * ML-KEM-768��Kyber-768��ʵ�֡�
 */
public class MlKem768 {
    private static final KyberParameters PARAMS = KyberParameters.kyber768;

    public KemEncapsulationResult encapsulate(byte[] publicKey) {
        try {
            KyberPublicKeyParameters pub = new KyberPublicKeyParameters(PARAMS, publicKey);
            KyberKEMGenerator generator = new KyberKEMGenerator(new SecureRandom());
            SecretWithEncapsulation secret = generator.generateEncapsulated(pub);
            return new KemEncapsulationResult(secret.getSecret(), secret.getEncapsulation());
        } catch (Exception e) {
            throw new CryptoException("ML-KEM-768 encapsulation failed", e);
        }
    }

    public byte[] decapsulate(byte[] privateKey, byte[] encapsulated) {
        try {
            KyberPrivateKeyParameters priv = new KyberPrivateKeyParameters(PARAMS, privateKey);
            KyberKEMExtractor extractor = new KyberKEMExtractor(priv);
            return extractor.extractSecret(encapsulated);
        } catch (Exception e) {
            throw new CryptoException("ML-KEM-768 decapsulation failed", e);
        }
    }
}
