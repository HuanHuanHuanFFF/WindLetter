package com.windletter.api.spi;

import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import java.util.Optional;

/**
 * Identity resolution interface.
 * <p>
 * Serves both sender-side signing leases and receiver-side identity lookups.
 */
public interface IdentityService {

    /**
     * Open a sender-side signing identity lease.
     */
    Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef signingIdentityRef);

    /**
     * Look up verification public key by signing kid.
     */
    Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String signingKid);

    /**
     * Look up sender display identity by signing kid.
     */
    Optional<SenderIdentity> resolveSenderBySigningKid(String signingKid);
}
