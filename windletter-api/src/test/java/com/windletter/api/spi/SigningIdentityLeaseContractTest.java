package com.windletter.api.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import org.junit.jupiter.api.Test;

class SigningIdentityLeaseContractTest {

    @Test
    void shouldCloseOwnedSigningHandleIdempotently() {
        Ed25519PrivateKeyHandle handle = new BouncyCastleEd25519Crypto().generatePrivateKey();
        SigningIdentityLease lease = SigningIdentityLease.ed25519("identity-1", "signing-kid", handle);

        assertEquals("identity-1", lease.identityId());
        assertEquals("signing-kid", lease.signingKid());
        assertSame(handle, lease.ed25519PrivateKey());

        lease.close();
        lease.close();

        assertThrows(IllegalStateException.class, lease::identityId);
        assertThrows(IllegalStateException.class, lease::signingKid);
        assertThrows(IllegalStateException.class, lease::ed25519PrivateKey);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldCloseOwnedSigningHandleWhenTryWithResourcesBodyThrows() {
        Ed25519PrivateKeyHandle handle = new BouncyCastleEd25519Crypto().generatePrivateKey();
        SigningIdentityLease lease = SigningIdentityLease.ed25519("identity-1", "signing-kid", handle);

        assertThrows(
            ExpectedFailure.class,
            () -> {
                try (lease) {
                    throw new ExpectedFailure();
                }
            }
        );

        assertThrows(IllegalStateException.class, lease::ed25519PrivateKey);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    private static final class ExpectedFailure extends RuntimeException {
    }
}
