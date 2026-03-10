package com.windletter.protocol.derivation;

import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;

/**
 * HKDF-based protocol derivation implementation skeleton.
 */
public final class HkdfKekDerivationCrypto implements KekDerivationCrypto {

    private final HkdfCrypto hkdfCrypto;

    /**
     * Create derivation crypto with default HKDF implementation.
     */
    public HkdfKekDerivationCrypto() {
        this(new BouncyCastleHkdfCrypto());
    }

    /**
     * Create derivation crypto with caller-provided HKDF implementation.
     */
    public HkdfKekDerivationCrypto(HkdfCrypto hkdfCrypto) {
        if (hkdfCrypto == null) {
            throw new IllegalArgumentException("hkdfCrypto must not be null");
        }
        this.hkdfCrypto = hkdfCrypto;
    }

    /**
     * Derive KEK or RID material by protocol derivation spec.
     */
    @Override
    public byte[] derive(KekDerivationSpec spec, byte[] ikm) {
        if (spec == null) {
            throw new IllegalArgumentException("spec must not be null");
        }
        if (ikm == null || ikm.length != spec.inputLength()) {
            throw new IllegalArgumentException("ikm length must be " + spec.inputLength() + " bytes for spec " + spec.id());
        }
        throw new CryptoOperationException("KekDerivation is not implemented yet for spec " + spec.id());
    }
}
