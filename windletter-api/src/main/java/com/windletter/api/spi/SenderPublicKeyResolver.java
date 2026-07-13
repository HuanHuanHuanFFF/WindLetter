package com.windletter.api.spi;

import java.util.Optional;

/**
 * Resolves sender public keys referenced by protocol key identifiers.
 */
public interface SenderPublicKeyResolver {

    /**
     * Resolve a sender X25519 public key by kid.
     */
    Optional<X25519PublicKeyMaterial> resolveX25519ByKid(String kid);
}
