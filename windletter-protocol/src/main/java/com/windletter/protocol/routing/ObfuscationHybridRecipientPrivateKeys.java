package com.windletter.protocol.routing;

import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;

/** Borrowed atomic private-key pair for one obfuscation-mode Hybrid identity. */
public record ObfuscationHybridRecipientPrivateKeys(
        X25519PrivateKeyHandle x25519PrivateKey,
        MLKem768PrivateKeyHandle mlkem768PrivateKey
) {
    public ObfuscationHybridRecipientPrivateKeys {
        if (x25519PrivateKey == null) {
            throw new IllegalArgumentException("x25519PrivateKey must not be null");
        }
        if (mlkem768PrivateKey == null) {
            throw new IllegalArgumentException("mlkem768PrivateKey must not be null");
        }
    }
}
