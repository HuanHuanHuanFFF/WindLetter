package com.windletter.protocol.derivation;

/**
 * Protocol-level derivation capability for KEK/rid materials.
 */
public interface KekDerivationCrypto {

    /**
     * Derive material by a derivation spec and input keying material.
     *
     * @param spec derivation spec
     * @param ikm input keying material
     * @return derived output bytes
     * @throws IllegalArgumentException if spec/ikm constraints are violated
     * @throws com.windletter.crypto.api.CryptoOperationException if derivation fails
     */
    byte[] derive(KekDerivationSpec spec, byte[] ikm);
}
