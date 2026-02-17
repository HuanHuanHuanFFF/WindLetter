package com.windletter.api;

import com.windletter.api.model.DecryptRequest;
import com.windletter.api.model.DecryptResult;

/**
 * Receiver-side facade interface.
 * <p>
 * This interface only defines inputs, outputs, and result semantics; concrete verify/decrypt flow is provided by implementations.
 */
public interface WindLetterReceiver {

    /**
     * Decrypt a message, with verification behavior determined by {@code DecryptRequest.verificationPolicy}.
     *
     * @param req receiver-side decrypt request
     * @return decrypt result including status, optional payload, and optional verification details
     * @throws IllegalArgumentException if request validation fails
     */
    DecryptResult decrypt(DecryptRequest req);

    /**
     * Decrypt and enforce verification semantics (implementations may be stricter than {@link #decrypt(DecryptRequest)}).
     *
     * @param req receiver-side decrypt request
     * @return decrypt result including status, optional payload, and verification outcome
     * @throws IllegalArgumentException if request validation fails
     */
    DecryptResult decryptAndVerify(DecryptRequest req);
}
