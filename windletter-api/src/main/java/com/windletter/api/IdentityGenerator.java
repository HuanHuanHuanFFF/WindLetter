package com.windletter.api;

import com.windletter.crypto.keys.EccKeyPair;
import com.windletter.crypto.keys.KeyGenerator;
import com.windletter.crypto.keys.PqcKemKeyPair;

/**
 * Generates WindIdentity with Ed25519 + X25519 (+ optional ML-KEM-768).
 * 生成包含 Ed25519 + X25519（可选 ML-KEM-768）的 WindIdentity。
 */
public class IdentityGenerator {
    private final KeyGenerator keyGenerator;
    private final boolean includePqc;

    public IdentityGenerator(KeyGenerator keyGenerator, boolean includePqc) {
        this.keyGenerator = keyGenerator;
        this.includePqc = includePqc;
    }

    public WindIdentity generate() {
        EccKeyPair sign = keyGenerator.generateEd25519();
        EccKeyPair kemEcc = keyGenerator.generateX25519();
        PqcKemKeyPair kemPqc = includePqc ? keyGenerator.generateMlKem768() : null;
        WindIdentity identity = new WindIdentity();
        identity.setWindId(sign.getKid());
        identity.setSignKey(sign);
        identity.setKemEccKey(kemEcc);
        identity.setKemPqcKey(kemPqc);
        return identity;
    }
}
