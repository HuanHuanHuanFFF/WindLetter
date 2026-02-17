package com.windletter.api.spi;

import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import java.util.Optional;

/**
 * Identity resolution interface.
 * <p>
 * Serves both sender-side (signing identity material) and receiver-side (verification public keys and sender display identity).
 */
public interface IdentityService {

    /**
     * Resolve sender-side signing identity material.
     */
    Optional<SigningIdentityMaterial> resolveSigningIdentity(SigningIdentityRef signingIdentityRef);

    /**
     * Look up verification public key by signing kid.
     */
    Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String signingKid);

    /**
     * Look up sender display identity by signing kid.
     */
    Optional<SenderIdentity> resolveSenderBySigningKid(String signingKid);
}
