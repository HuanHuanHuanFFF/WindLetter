package com.windletter.api.spi;

import com.windletter.api.model.RecipientRef;
import java.util.Optional;

/**
 * Resolves recipient public-key material for sender-side encryption.
 */
public interface RecipientPublicKeyResolver {

    /**
     * Resolve public-key material for a recipient reference.
     */
    Optional<RecipientPublicKeyMaterial> resolve(RecipientRef recipient);
}
