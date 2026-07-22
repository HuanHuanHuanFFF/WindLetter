package com.windletter.api;

import com.windletter.api.impl.DefaultWindLetterReceiver;
import com.windletter.api.impl.DefaultWindLetterSender;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientKeyStore;
import com.windletter.api.spi.RecipientPublicKeyResolver;
import com.windletter.api.spi.SenderEncryptionKeyStore;
import com.windletter.api.spi.SenderPublicKeyResolver;

/**
 * Minimal composition root for the default Wind Letter v1.0 implementation.
 *
 * <p>The returned facades use the production protocol flows and cryptographic providers. They
 * support raw JSON wire data plus the binary, Base64URL and WindBase1024F v1 transport armors.
 */
public final class WindLetterRuntime {

    private WindLetterRuntime() {
    }

    /** Creates a sender backed by application-owned recipient and identity services. */
    public static WindLetterSender sender(
        RecipientPublicKeyResolver recipientKeys,
        SenderEncryptionKeyStore senderEncryptionKeys,
        IdentityService identities
    ) {
        return new DefaultWindLetterSender(
            recipientKeys,
            senderEncryptionKeys,
            identities
        );
    }

    /** Creates a receiver backed by application-owned private-key and trust services. */
    public static WindLetterReceiver receiver(
        RecipientKeyStore recipientKeys,
        SenderPublicKeyResolver senderKeys,
        IdentityService identities
    ) {
        return new DefaultWindLetterReceiver(recipientKeys, senderKeys, identities);
    }
}
