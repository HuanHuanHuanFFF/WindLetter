package com.windletter.api.spi;

import com.windletter.api.model.SenderEncryptionIdentityRef;
import java.util.Optional;

/**
 * Sender-side encryption private-key lease provider.
 */
public interface SenderEncryptionKeyStore {

    /**
     * Open the encryption key selected by the supplied sender identity reference.
     */
    Optional<SenderEncryptionKeyLease> open(SenderEncryptionIdentityRef identity);
}
