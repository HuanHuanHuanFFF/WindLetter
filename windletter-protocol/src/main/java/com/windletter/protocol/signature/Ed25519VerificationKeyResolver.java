package com.windletter.protocol.signature;

import java.util.Optional;

/** Resolves a locally trusted Ed25519 verification key by its signing kid. */
@FunctionalInterface
public interface Ed25519VerificationKeyResolver {

    Optional<TrustedEd25519Key> resolve(String signingKid);
}
