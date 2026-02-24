package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
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
import java.util.Arrays;

/**
 * Bouncy Castle-based ML-KEM-768 implementation scaffold.
 */
public final class BouncyCastleMLKem768Crypto implements MLKem768Crypto {

    private static final int PRIVATE_KEY_LEN = 2400;
    private static final int PUBLIC_KEY_LEN = 1184;
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
    public MLKem768PrivateKeyHandle generatePrivateKey() {
        try {
            MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
            generator.init(new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768));
            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
            MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
            return new Handle(privateKey.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to generate ML-KEM-768 private key", e);
        }
    }

    @Override
    public MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey) {
        validatePrivateKey(privateKey);
        try {
            MLKEMPrivateKeyParameters privateKeyParams = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privateKey);
            MLKEMPublicKeyParameters publicKey = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, privateKeyParams.getPublicKey());
            return new Handle(privateKeyParams.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to import ML-KEM-768 private key", e);
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
    public byte[] decapsulate(MLKem768PrivateKeyHandle privateKey, byte[] ciphertext) {
        Handle internalHandle = requireHandle(privateKey);
        validateCiphertext(ciphertext);
        internalHandle.ensureNotDestroyed();
        try {
            MLKEMExtractor extractor = new MLKEMExtractor(
                    new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, internalHandle.privateKey));
            return extractor.extractSecret(ciphertext);
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to decapsulate with ML-KEM-768", e);
        }
    }

    private static void validatePublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("publicKey must be " + PUBLIC_KEY_LEN + " bytes");
        }
    }

    private static void validatePrivateKey(byte[] privateKey) {
        if (privateKey == null || privateKey.length != PRIVATE_KEY_LEN) {
            throw new IllegalArgumentException("privateKey must be " + PRIVATE_KEY_LEN + " bytes");
        }
    }

    private static void validateCiphertext(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length != MLKem768Encapsulation.CIPHERTEXT_LEN) {
            throw new IllegalArgumentException("ciphertext must be " + MLKem768Encapsulation.CIPHERTEXT_LEN + " bytes");
        }
    }

    private static Handle requireHandle(MLKem768PrivateKeyHandle privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        if (!(privateKey instanceof Handle handle)) {
            throw new IllegalArgumentException("privateKey was not created by this ML-KEM-768 crypto implementation");
        }
        return handle;
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

    private static final class Handle implements MLKem768PrivateKeyHandle {
        private byte[] privateKey;
        private final byte[] publicKey;

        private Handle(byte[] privateKey, byte[] publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        @Override
        public byte[] publicKey() {
            ensureNotDestroyed();
            return publicKey.clone();
        }

        @Override
        public void close() {
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
                privateKey = null;
            }
        }

        private void ensureNotDestroyed() {
            if (privateKey == null) {
                throw new IllegalStateException("private key handle is destroyed");
            }
        }
    }
}
