package com.windletter.protocol.flow;

import java.util.Optional;

/** Resolves the sender's X25519 public key from its public-mode key identifier. */
@FunctionalInterface
public interface SenderX25519PublicKeyResolver {

    Optional<byte[]> resolve(String x25519Kid);
}
