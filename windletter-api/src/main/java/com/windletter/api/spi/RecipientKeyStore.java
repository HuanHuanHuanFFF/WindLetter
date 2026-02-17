package com.windletter.api.spi;

import com.windletter.api.model.RecipientIdentityRef;
import java.util.List;
import java.util.Optional;

/**
 * Receiver-side key lookup interface.
 * <p>
 * findPrimary is for the fast path; findAll is for key rotation or fallback attempts.
 */
public interface RecipientKeyStore {

    /**
     * Look up the preferred decryption key.
     */
    Optional<DecryptionKeyMaterial> findPrimary(RecipientIdentityRef recipientIdentityRef);

    /**
     * Look up candidate decryption keys.
     */
    List<DecryptionKeyMaterial> findAll(RecipientIdentityRef recipientIdentityRef);
}
