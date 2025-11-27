package com.windletter.crypto.kem;

import com.windletter.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * ECDH-ES using X25519 for deriving shared secrets.
 * 使用 X25519 的 ECDH-ES 共享密钥派生。
 */
public class X25519KeyAgreement {

    public byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey) {
        if (privateKey == null || privateKey.length != X25519PrivateKeyParameters.KEY_SIZE) {
            throw new CryptoException("X25519 private key must be 32 bytes");
        }
        if (peerPublicKey == null || peerPublicKey.length != X25519PublicKeyParameters.KEY_SIZE) {
            throw new CryptoException("X25519 public key must be 32 bytes");
        }
        try {
            X25519PrivateKeyParameters priv = new X25519PrivateKeyParameters(privateKey, 0);
            X25519PublicKeyParameters pub = new X25519PublicKeyParameters(peerPublicKey, 0);
            X25519Agreement agreement = new X25519Agreement();
            agreement.init(priv);
            byte[] secret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(pub, secret, 0);
            return secret;
        } catch (Exception e) {
            throw new CryptoException("X25519 agreement failed", e);
        }
    }
}
