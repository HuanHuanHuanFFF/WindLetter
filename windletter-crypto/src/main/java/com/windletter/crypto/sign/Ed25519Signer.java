package com.windletter.crypto.sign;

import com.windletter.crypto.CryptoException;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

/**
 * Ed25519 signing/verification adapter.
 * Ed25519 签名与验签适配器。
 */
public class Ed25519Signer {

    public byte[] sign(byte[] privateKey, byte[] message) {
        try {
            Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(privateKey, 0);
            org.bouncycastle.crypto.signers.Ed25519Signer signer = new org.bouncycastle.crypto.signers.Ed25519Signer();
            byte[] msg = message == null ? new byte[0] : message;
            signer.init(true, priv);
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new CryptoException("Ed25519 signing failed", e);
        }
    }

    public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(publicKey, 0);
            org.bouncycastle.crypto.signers.Ed25519Signer verifier = new org.bouncycastle.crypto.signers.Ed25519Signer();
            byte[] msg = message == null ? new byte[0] : message;
            verifier.init(false, pub);
            verifier.update(msg, 0, msg.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            throw new CryptoException("Ed25519 verification failed", e);
        }
    }
}
