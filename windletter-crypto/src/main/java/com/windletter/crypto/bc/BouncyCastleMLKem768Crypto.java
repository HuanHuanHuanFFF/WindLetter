package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768KeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;

/**
 * Bouncy Castle-based ML-KEM-768 implementation scaffold.
 */
public final class BouncyCastleMLKem768Crypto implements MLKem768Crypto {

    private final SecureRandom secureRandom;

    public BouncyCastleMLKem768Crypto() {
        this(new SecureRandom());
    }

    public BouncyCastleMLKem768Crypto(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.secureRandom = secureRandom;
    }

    @Override
    public MLKem768KeyPair generateKeyPair() {
        try {
            MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
            generator.init(new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768));

            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
            MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
            MLKem768KeyPair result = new MLKem768KeyPair(privateKey.getEncoded(), publicKey.getEncoded());
            return result;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to generate ML-KEM-768 key pair", e);
        }
    }

    @Override
    public MLKem768Encapsulation encapsulate(byte[] publicKey) {
        validatePublicKey(publicKey);
        SecretWithEncapsulation kemResult = null;
        try {
            MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
            kemResult = generator.generateEncapsulated(
                    new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, publicKey));

            byte[] secret = kemResult.getSecret().clone();
            byte[] encapsulation = kemResult.getEncapsulation().clone();
            MLKem768Encapsulation result = new MLKem768Encapsulation(encapsulation, secret);
            return result;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to encapsulate with ML-KEM-768", e);
        } finally {
            destroyQuietly(kemResult);
        }
    }

    @Override
    public byte[] decapsulate(byte[] privateKey, byte[] ciphertext) {
        validatePrivateKey(privateKey);
        validateCiphertext(ciphertext);
        try {
            MLKEMExtractor extractor = new MLKEMExtractor(
                    new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privateKey));
            byte[] secret = extractor.extractSecret(ciphertext);
            return secret;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to decapsulate with ML-KEM-768", e);
        }
    }

    private static void validatePublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != MLKem768KeyPair.PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("publicKey must be " + MLKem768KeyPair.PUBLIC_KEY_LEN + " bytes");
        }
    }

    private static void validatePrivateKey(byte[] privateKey) {
        if (privateKey == null || privateKey.length != MLKem768KeyPair.PRIVATE_KEY_LEN) {
            throw new IllegalArgumentException("privateKey must be " + MLKem768KeyPair.PRIVATE_KEY_LEN + " bytes");
        }
    }

    private static void validateCiphertext(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length != MLKem768Encapsulation.CIPHERTEXT_LEN) {
            throw new IllegalArgumentException("ciphertext must be " + MLKem768Encapsulation.CIPHERTEXT_LEN + " bytes");
        }
    }

    private static void destroyQuietly(SecretWithEncapsulation kemResult) {
        if (kemResult == null) {
            return;
        }
        try {
            kemResult.destroy();
        } catch (Exception ignored) {
            // Best-effort cleanup for provider-side secret holder.
        }
    }
}
