package com.windletter.protocol.routing;

import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;

/** Borrowed X25519/ML-KEM-768 private-key pair for one local recipient identity. */
public record PublicHybridRecipientPrivateKeys(
        X25519PrivateKeyHandle x25519PrivateKey,
        MLKem768PrivateKeyHandle mlkem768PrivateKey
) {
    public PublicHybridRecipientPrivateKeys {
        if (x25519PrivateKey == null) {
            throw new IllegalArgumentException("x25519PrivateKey must not be null");
        }
        if (mlkem768PrivateKey == null) {
            throw new IllegalArgumentException("mlkem768PrivateKey must not be null");
        }
    }
}
