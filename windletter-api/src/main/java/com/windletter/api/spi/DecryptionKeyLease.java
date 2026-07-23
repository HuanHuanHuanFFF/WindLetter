package com.windletter.api.spi;

import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owned receiver-side private-key handles for one decryption candidate.
 */
public final class DecryptionKeyLease implements AutoCloseable {

    private final String x25519Kid;
    private final X25519PrivateKeyHandle x25519PrivateKey;
    private final String mlkem768Kid;
    private final MLKem768PrivateKeyHandle mlkem768PrivateKey;
    private final AtomicBoolean closed = new AtomicBoolean();

    private DecryptionKeyLease(
        String x25519Kid,
        X25519PrivateKeyHandle x25519PrivateKey,
        String mlkem768Kid,
        MLKem768PrivateKeyHandle mlkem768PrivateKey
    ) {
        this.x25519Kid = SpiChecks.requireNonBlank(x25519Kid, "x25519Kid");
        this.x25519PrivateKey = requireHandle(x25519PrivateKey, "x25519PrivateKey");
        this.mlkem768Kid = mlkem768Kid;
        this.mlkem768PrivateKey = mlkem768PrivateKey;
    }

    public static DecryptionKeyLease x25519(String kid, X25519PrivateKeyHandle key) {
        return new DecryptionKeyLease(kid, key, null, null);
    }

    public static DecryptionKeyLease hybrid(
        String x25519Kid,
        X25519PrivateKeyHandle x25519PrivateKey,
        String mlkem768Kid,
        MLKem768PrivateKeyHandle mlkem768PrivateKey
    ) {
        return new DecryptionKeyLease(
            x25519Kid,
            x25519PrivateKey,
            SpiChecks.requireNonBlank(mlkem768Kid, "mlkem768Kid"),
            requireHandle(mlkem768PrivateKey, "mlkem768PrivateKey")
        );
    }

    public String x25519Kid() {
        ensureOpen();
        return x25519Kid;
    }

    public X25519PrivateKeyHandle x25519PrivateKey() {
        ensureOpen();
        return x25519PrivateKey;
    }

    public String mlkem768Kid() {
        ensureOpen();
        return mlkem768Kid;
    }

    public MLKem768PrivateKeyHandle mlkem768PrivateKey() {
        ensureOpen();
        return mlkem768PrivateKey;
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        Throwable failure = closeCapturing(x25519PrivateKey, null);
        failure = closeCapturing(mlkem768PrivateKey, failure);
        rethrow(failure);
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("decryption key lease is closed");
        }
    }

    private static Throwable closeCapturing(AutoCloseable handle, Throwable failure) {
        if (handle == null) {
            return failure;
        }
        try {
            handle.close();
        } catch (RuntimeException | Error closeFailure) {
            if (failure == null) {
                return closeFailure;
            }
            failure.addSuppressed(closeFailure);
        } catch (Exception impossible) {
            throw new AssertionError("private-key handle declared an unexpected checked close failure", impossible);
        }
        return failure;
    }

    private static void rethrow(Throwable failure) {
        if (failure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        if (failure instanceof Error error) {
            throw error;
        }
    }

    private static <T> T requireHandle(T handle, String field) {
        if (handle == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return handle;
    }
}
