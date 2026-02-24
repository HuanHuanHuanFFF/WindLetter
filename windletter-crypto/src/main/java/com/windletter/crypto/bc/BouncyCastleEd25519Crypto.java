package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Bouncy Castle-based Ed25519 implementation.
 */
public final class BouncyCastleEd25519Crypto implements Ed25519Crypto {

    private final SecureRandom secureRandom;

    public BouncyCastleEd25519Crypto() {
        this(new SecureRandom());
    }

    public BouncyCastleEd25519Crypto(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.secureRandom = secureRandom;
    }

    @Override
    public Ed25519PrivateKeyHandle generatePrivateKey() {
        try {
            Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
            generator.init(new Ed25519KeyGenerationParameters(secureRandom));
            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
            Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
            return new Handle(privateKey.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to generate Ed25519 private key", e);
        }
    }

    @Override
    public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
        validatePrivateKey(privateKey);
        try {
            Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(privateKey, 0);
            Ed25519PublicKeyParameters publicKey = privateKeyParams.generatePublicKey();
            return new Handle(privateKeyParams.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to import Ed25519 private key", e);
        }
    }

    @Override
    public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
        Handle internalHandle = requireHandle(privateKey);
        validateMessage(message);
        internalHandle.ensureNotDestroyed();
        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, new Ed25519PrivateKeyParameters(internalHandle.privateKey, 0));
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to sign with Ed25519", e);
        }
    }

    @Override
    public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        validatePublicKey(publicKey);
        validateMessage(message);
        validateSignature(signature);
        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            signer.update(message, 0, message.length);
            boolean ok = signer.verifySignature(signature);
            return ok;
        } catch (IllegalArgumentException e) {
            // Malformed key/signature payload should be treated as verification failure.
            return false;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to verify Ed25519 signature", e);
        }
    }

    private static void validatePublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != 32) {
            throw new IllegalArgumentException("publicKey must be 32 bytes");
        }
    }

    private static void validatePrivateKey(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("privateKey must be 32 bytes");
        }
    }

    private static void validateMessage(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }
    }

    private static void validateSignature(byte[] signature) {
        if (signature == null || signature.length != 64) {
            throw new IllegalArgumentException("signature must be 64 bytes");
        }
    }

    private static Handle requireHandle(Ed25519PrivateKeyHandle privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        if (!(privateKey instanceof Handle handle)) {
            throw new IllegalArgumentException("privateKey was not created by this Ed25519 crypto implementation");
        }
        return handle;
    }

    private static final class Handle implements Ed25519PrivateKeyHandle {
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
