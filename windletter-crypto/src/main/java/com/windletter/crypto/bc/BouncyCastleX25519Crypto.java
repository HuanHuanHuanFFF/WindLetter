package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Bouncy Castle-based X25519 implementation.
 */
public final class BouncyCastleX25519Crypto implements X25519Crypto {

    private final SecureRandom secureRandom;

    public BouncyCastleX25519Crypto() {
        this(new SecureRandom());
    }

    public BouncyCastleX25519Crypto(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.secureRandom = secureRandom;
    }

    @Override
    public X25519PrivateKeyHandle generatePrivateKey() {
        try {
            X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(secureRandom);
            X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
            return new Handle(privateKey.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to generate X25519 private key", e);
        }
    }

    @Override
    public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
        validatePrivateKey(privateKey);
        try {
            X25519PrivateKeyParameters privateKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
            X25519PublicKeyParameters publicKey = privateKeyParams.generatePublicKey();
            return new Handle(privateKeyParams.getEncoded(), publicKey.getEncoded());
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to import X25519 private key", e);
        }
    }

    @Override
    public byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey) {
        Handle internalHandle = requireHandle(privateKey);
        validatePeerPublicKey(peerPublicKey);
        internalHandle.ensureNotDestroyed();
        if (isAllZero(peerPublicKey)) {
            throw new CryptoOperationException("failed to derive X25519 shared secret: low-order public key");
        }
        byte[] shared = new byte[32];
        boolean success = false;
        try {
            X25519PrivateKeyParameters privateKeyParams = new X25519PrivateKeyParameters(internalHandle.privateKey, 0);
            X25519PublicKeyParameters publicKeyParams = new X25519PublicKeyParameters(peerPublicKey, 0);
            privateKeyParams.generateSecret(publicKeyParams, shared, 0);
            if (isAllZero(shared)) {
                throw new CryptoOperationException("failed to derive X25519 shared secret: low-order public key");
            }
            success = true;
            return shared;
        } catch (CryptoOperationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to derive X25519 shared secret", e);
        } finally {
            if (!success) {
                Arrays.fill(shared, (byte) 0);
            }
        }
    }

    private static boolean isAllZero(byte[] value) {
        int acc = 0;
        for (byte b : value) {
            acc |= b;
        }
        return acc == 0;
    }

    private static Handle requireHandle(X25519PrivateKeyHandle privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        if (!(privateKey instanceof Handle handle)) {
            throw new IllegalArgumentException("privateKey was not created by this X25519 crypto implementation");
        }
        return handle;
    }

    private static void validatePeerPublicKey(byte[] peerPublicKey) {
        if (peerPublicKey == null || peerPublicKey.length != 32) {
            throw new IllegalArgumentException("peerPublicKey must be 32 bytes");
        }
    }

    private static void validatePrivateKey(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("privateKey must be 32 bytes");
        }
    }

    private static final class Handle implements X25519PrivateKeyHandle {
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
