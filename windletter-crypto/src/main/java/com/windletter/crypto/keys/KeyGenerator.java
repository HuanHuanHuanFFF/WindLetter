package com.windletter.crypto.keys;

import com.windletter.core.encoding.Base64Url;
import com.windletter.crypto.hash.WindHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import java.security.SecureRandom;

/**
 * Simple key generator for Ed25519, X25519, and ML-KEM-768.
 * 简单的密钥生成器，生成 Ed25519、X25519 与 ML-KEM-768 密钥对。
 */
public class KeyGenerator {
    private final SecureRandom random = new SecureRandom();
    private final WindHash hash = new WindHash();

    public EccKeyPair generateEd25519() {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(random);
        Ed25519PublicKeyParameters pub = priv.generatePublicKey();
        String kid = kidFromPublic(pub.getEncoded());
        return new EccKeyPair(kid, pub.getEncoded(), priv.getEncoded());
    }

    public EccKeyPair generateX25519() {
        X25519PrivateKeyParameters priv = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters pub = priv.generatePublicKey();
        String kid = kidFromPublic(pub.getEncoded());
        return new EccKeyPair(kid, pub.getEncoded(), priv.getEncoded());
    }

    public PqcKemKeyPair generateMlKem768() {
        KyberKeyPairGenerator gen = new KyberKeyPairGenerator();
        gen.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber768));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        KyberPublicKeyParameters pub = (KyberPublicKeyParameters) kp.getPublic();
        KyberPrivateKeyParameters priv = (KyberPrivateKeyParameters) kp.getPrivate();
        String kid = kidFromPublic(pub.getEncoded());
        return new PqcKemKeyPair(kid, pub.getEncoded(), priv.getEncoded());
    }

    private String kidFromPublic(byte[] pub) {
        byte[] digest = hash.sha256(pub);
        return Base64Url.encode(digest);
    }
}
