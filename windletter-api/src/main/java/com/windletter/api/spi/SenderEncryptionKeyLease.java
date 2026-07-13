package com.windletter.api.spi;

import com.windletter.crypto.api.X25519PrivateKeyHandle;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owned sender-side X25519 private-key handle.
 */
public final class SenderEncryptionKeyLease implements AutoCloseable {

    private final String kid;
    private final X25519PrivateKeyHandle x25519PrivateKey;
    private final AtomicBoolean closed = new AtomicBoolean();

    private SenderEncryptionKeyLease(String kid, X25519PrivateKeyHandle x25519PrivateKey) {
        this.kid = SpiChecks.requireNonBlank(kid, "kid");
        this.x25519PrivateKey = requireHandle(x25519PrivateKey, "x25519PrivateKey");
    }

    public static SenderEncryptionKeyLease x25519(String kid, X25519PrivateKeyHandle x25519PrivateKey) {
        return new SenderEncryptionKeyLease(kid, x25519PrivateKey);
    }

    public String kid() {
        ensureOpen();
        return kid;
    }

    public X25519PrivateKeyHandle x25519PrivateKey() {
        ensureOpen();
        return x25519PrivateKey;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            x25519PrivateKey.close();
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("sender encryption key lease is closed");
        }
    }

    private static <T> T requireHandle(T handle, String field) {
        if (handle == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return handle;
    }
}
