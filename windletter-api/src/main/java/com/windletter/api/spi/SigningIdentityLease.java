package com.windletter.api.spi;

import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owned sender-side signing identity and Ed25519 private-key handle.
 */
public final class SigningIdentityLease implements AutoCloseable {

    private final String identityId;
    private final String signingKid;
    private final Ed25519PrivateKeyHandle ed25519PrivateKey;
    private final AtomicBoolean closed = new AtomicBoolean();

    private SigningIdentityLease(
        String identityId,
        String signingKid,
        Ed25519PrivateKeyHandle ed25519PrivateKey
    ) {
        this.identityId = SpiChecks.requireNonBlank(identityId, "identityId");
        this.signingKid = SpiChecks.requireNonBlank(signingKid, "signingKid");
        this.ed25519PrivateKey = requireHandle(ed25519PrivateKey, "ed25519PrivateKey");
    }

    public static SigningIdentityLease ed25519(
        String identityId,
        String signingKid,
        Ed25519PrivateKeyHandle ed25519PrivateKey
    ) {
        return new SigningIdentityLease(identityId, signingKid, ed25519PrivateKey);
    }

    public String identityId() {
        ensureOpen();
        return identityId;
    }

    public String signingKid() {
        ensureOpen();
        return signingKid;
    }

    public Ed25519PrivateKeyHandle ed25519PrivateKey() {
        ensureOpen();
        return ed25519PrivateKey;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            ed25519PrivateKey.close();
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("signing identity lease is closed");
        }
    }

    private static <T> T requireHandle(T handle, String field) {
        if (handle == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return handle;
    }
}
