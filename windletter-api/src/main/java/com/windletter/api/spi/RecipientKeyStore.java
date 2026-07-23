package com.windletter.api.spi;

import com.windletter.api.model.RecipientIdentityRef;
import java.util.List;

/**
 * Receiver-side private-key lease provider.
 */
public interface RecipientKeyStore {

    /**
     * Open candidate decryption keys for key rotation or fallback attempts.
     */
    List<DecryptionKeyLease> openAll(RecipientIdentityRef recipientIdentityRef);
}
