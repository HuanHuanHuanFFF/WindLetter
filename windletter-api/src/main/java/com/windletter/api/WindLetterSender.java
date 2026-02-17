package com.windletter.api;

import com.windletter.api.model.EncryptAndSignRequest;
import com.windletter.api.model.EncryptRequest;
import com.windletter.api.model.EncryptedMessage;

/**
 * Sender-side facade interface.
 * <p>
 * This interface only defines the call contract and does not include protocol orchestration or cryptographic implementation.
 */
public interface WindLetterSender {

    /**
     * Encrypt only, without signing.
     *
     * @param req sender-side encryption request
     * @return encrypted message in stable wire container form
     * @throws IllegalArgumentException if request validation fails
     */
    EncryptedMessage encrypt(EncryptRequest req);

    /**
     * Encrypt and attach a signature.
     *
     * @param req sender-side encrypt-and-sign request
     * @return encrypted message in stable wire container form
     * @throws IllegalArgumentException if request validation fails
     */
    EncryptedMessage encryptAndSign(EncryptAndSignRequest req);
}
