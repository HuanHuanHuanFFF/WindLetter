package com.windletter.crypto.bc;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519KeyPair;
import java.security.SecureRandom;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

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
    public X25519KeyPair generateKeyPair() {
        try {
            X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(secureRandom);
            X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
            X25519KeyPair result = new X25519KeyPair(privateKey.getEncoded(), publicKey.getEncoded());
            return result;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to generate X25519 key pair", e);
        }
    }

    @Override
    public byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("privateKey must be 32 bytes");
        }
        if (peerPublicKey == null || peerPublicKey.length != 32) {
            throw new IllegalArgumentException("peerPublicKey must be 32 bytes");
        }

        try {
            X25519PrivateKeyParameters privateKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
            X25519PublicKeyParameters publicKeyParams = new X25519PublicKeyParameters(peerPublicKey, 0);
            byte[] shared = new byte[32];
            privateKeyParams.generateSecret(publicKeyParams, shared, 0);
            return shared;
        } catch (RuntimeException e) {
            throw new CryptoOperationException("failed to derive X25519 shared secret", e);
        }
    }
}
