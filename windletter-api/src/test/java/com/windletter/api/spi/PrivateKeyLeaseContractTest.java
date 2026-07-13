package com.windletter.api.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import java.lang.reflect.Method;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PrivateKeyLeaseContractTest {

    @Test
    void shouldCloseOwnedSenderEncryptionHandleIdempotently() {
        X25519PrivateKeyHandle handle = new BouncyCastleX25519Crypto().generatePrivateKey();
        SenderEncryptionKeyLease lease = SenderEncryptionKeyLease.x25519("sender-kid", handle);

        assertEquals("sender-kid", lease.kid());
        assertSame(handle, lease.x25519PrivateKey());

        lease.close();
        lease.close();

        assertThrows(IllegalStateException.class, lease::kid);
        assertThrows(IllegalStateException.class, lease::x25519PrivateKey);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldCloseOwnedDecryptionHandleIdempotently() {
        X25519PrivateKeyHandle handle = new BouncyCastleX25519Crypto().generatePrivateKey();
        DecryptionKeyLease lease = DecryptionKeyLease.x25519("recipient-kid", handle);

        assertEquals("recipient-kid", lease.x25519Kid());
        assertSame(handle, lease.x25519PrivateKey());

        lease.close();
        lease.close();

        assertThrows(IllegalStateException.class, lease::x25519Kid);
        assertThrows(IllegalStateException.class, lease::x25519PrivateKey);
        assertThrows(IllegalStateException.class, lease::mlkem768Kid);
        assertThrows(IllegalStateException.class, lease::mlkem768PrivateKey);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldCloseBothOwnedHybridHandles() {
        X25519PrivateKeyHandle x25519Handle = new BouncyCastleX25519Crypto().generatePrivateKey();
        MLKem768PrivateKeyHandle mlkem768Handle = new BouncyCastleMLKem768Crypto().generatePrivateKey();
        DecryptionKeyLease lease = DecryptionKeyLease.hybrid(
            "x-kid",
            x25519Handle,
            "pq-kid",
            mlkem768Handle
        );

        assertEquals("x-kid", lease.x25519Kid());
        assertSame(x25519Handle, lease.x25519PrivateKey());
        assertEquals("pq-kid", lease.mlkem768Kid());
        assertSame(mlkem768Handle, lease.mlkem768PrivateKey());

        lease.close();

        assertThrows(IllegalStateException.class, x25519Handle::publicKey);
        assertThrows(IllegalStateException.class, mlkem768Handle::publicKey);
    }

    @Test
    void shouldAttemptClosingMlkem768HandleWhenX25519CloseFails() {
        RuntimeException x25519Failure = new RuntimeException("x25519 close failed");
        ThrowingX25519Handle x25519Handle = new ThrowingX25519Handle(x25519Failure);
        RecordingMLKem768Handle mlkem768Handle = new RecordingMLKem768Handle(null);
        DecryptionKeyLease lease = DecryptionKeyLease.hybrid(
            "x-kid",
            x25519Handle,
            "pq-kid",
            mlkem768Handle
        );

        RuntimeException thrown = assertThrows(RuntimeException.class, lease::close);

        assertSame(x25519Failure, thrown);
        assertTrue(mlkem768Handle.closeCalled());
    }

    @Test
    void shouldSuppressMlkem768CloseFailureWhenBothHybridHandlesFail() {
        RuntimeException x25519Failure = new RuntimeException("x25519 close failed");
        RuntimeException mlkem768Failure = new RuntimeException("mlkem768 close failed");
        ThrowingX25519Handle x25519Handle = new ThrowingX25519Handle(x25519Failure);
        RecordingMLKem768Handle mlkem768Handle = new RecordingMLKem768Handle(mlkem768Failure);
        DecryptionKeyLease lease = DecryptionKeyLease.hybrid(
            "x-kid",
            x25519Handle,
            "pq-kid",
            mlkem768Handle
        );

        RuntimeException thrown = assertThrows(RuntimeException.class, lease::close);

        assertSame(x25519Failure, thrown);
        assertTrue(mlkem768Handle.closeCalled());
        assertEquals(1, thrown.getSuppressed().length);
        assertSame(mlkem768Failure, thrown.getSuppressed()[0]);
    }

    @Test
    void shouldCloseOwnedHandleWhenTryWithResourcesBodyThrows() {
        X25519PrivateKeyHandle handle = new BouncyCastleX25519Crypto().generatePrivateKey();
        SenderEncryptionKeyLease lease = SenderEncryptionKeyLease.x25519("sender-kid", handle);

        assertThrows(
            ExpectedFailure.class,
            () -> {
                try (lease) {
                    throw new ExpectedFailure();
                }
            }
        );

        assertThrows(IllegalStateException.class, lease::x25519PrivateKey);
        assertThrows(IllegalStateException.class, handle::publicKey);
    }

    @Test
    void shouldNotExposePrivateKeyByteArraysFromLeasePublicMethods() {
        assertNoByteArrayReturnType(SenderEncryptionKeyLease.class);
        assertNoByteArrayReturnType(DecryptionKeyLease.class);
        assertNoByteArrayReturnType(SigningIdentityLease.class);
    }

    private static void assertNoByteArrayReturnType(Class<?> leaseType) {
        boolean exposesByteArray = Arrays.stream(leaseType.getMethods())
            .map(Method::getReturnType)
            .anyMatch(byte[].class::equals);
        assertFalse(exposesByteArray, leaseType.getSimpleName() + " must not expose private key byte arrays");
    }

    private static final class ExpectedFailure extends RuntimeException {
    }

    private static final class ThrowingX25519Handle implements X25519PrivateKeyHandle {

        private final RuntimeException closeFailure;

        private ThrowingX25519Handle(RuntimeException closeFailure) {
            this.closeFailure = closeFailure;
        }

        @Override
        public byte[] publicKey() {
            return new byte[32];
        }

        @Override
        public void close() {
            throw closeFailure;
        }
    }

    private static final class RecordingMLKem768Handle implements MLKem768PrivateKeyHandle {

        private final RuntimeException closeFailure;
        private boolean closeCalled;

        private RecordingMLKem768Handle(RuntimeException closeFailure) {
            this.closeFailure = closeFailure;
        }

        @Override
        public byte[] publicKey() {
            return new byte[1184];
        }

        @Override
        public void close() {
            closeCalled = true;
            if (closeFailure != null) {
                throw closeFailure;
            }
        }

        private boolean closeCalled() {
            return closeCalled;
        }
    }
}
