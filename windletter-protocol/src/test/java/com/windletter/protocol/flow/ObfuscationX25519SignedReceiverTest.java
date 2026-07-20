package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.routing.ObfuscationX25519CekRecovery;
import com.windletter.protocol.signature.TrustedEd25519Key;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519SignedReceiverTest {

    @Test
    void receivesRealSignedWireClearsAllOwnedArraysAndReturnsOnlyTrustedIdentity() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            RecordingKeyWrap keyWrap = new RecordingKeyWrap(
                    fixture.keyWrap, WrapMode.DELEGATE
            );
            RecordingGcm gcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
            RecordingEd25519 verifier = new RecordingEd25519(
                    fixture.ed25519, VerifyMode.DELEGATE
            );
            TrustedEd25519Key trusted = fixture.trustedSigningKey();
            byte[] callerPublicBefore = trusted.publicKey();
            ObfuscationX25519SignedReceiver receiver = receiver(
                    fixture, keyWrap, gcm, verifier
            );

            ObfuscationX25519SignedReceiver.Result result = receiver.receive(
                    fixture.signedRequest(wire, kid -> Optional.of(trusted),
                            List.of(fixture.second))
            );

            assertArrayEquals(BINARY, result.payload().data());
            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                    result.authenticationStatus());
            assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
            assertEquals(fixture.signingKid, result.authenticatedSender().signingKid());
            assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad, gcm.plaintext,
                    verifier.publicKey, verifier.message, verifier.signature);
            assertArrayEquals(callerPublicBefore, trusted.publicKey(),
                    "trusted resolver record remains caller-owned");
            assertEquals(32, fixture.second.publicKey().length,
                    "recipient handle remains borrowed/open");
            clear(callerPublicBefore);
        }
    }

    @Test
    void wrongProfileAndRecoveryFailurePrecedeSignerResolutionAndVerification() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            AtomicInteger resolverCalls = new AtomicInteger();
            RecordingEd25519 verifier = new RecordingEd25519(
                    fixture.ed25519, VerifyMode.DELEGATE
            );
            ObfuscationX25519SignedReceiver receiver = receiver(
                    fixture,
                    new RecordingKeyWrap(fixture.keyWrap, WrapMode.DELEGATE),
                    new RecordingGcm(fixture.gcm, GcmMode.DELEGATE),
                    verifier
            );
            List<X25519PrivateKeyHandle> poisoned = Arrays.asList(
                    (X25519PrivateKeyHandle) null
            );

            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> receiver.receive(
                    fixture.signedRequest(protectedField(wire, "cty", "wind+inner"), kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, poisoned)
            ));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);

            assertCode(ErrorCode.INTERNAL_ERROR, () -> receiver.receive(
                    fixture.signedRequest(wire, kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, poisoned)
            ));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);

            assertCode(ErrorCode.NOT_FOR_ME, () -> receiver.receive(
                    fixture.signedRequest(wire, kid -> {
                        resolverCalls.incrementAndGet();
                        return Optional.of(fixture.trustedSigningKey());
                    }, List.of(fixture.unrelated))
            ));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);
        }
    }

    @Test
    void recoveryAndGcmProviderContractsKeepTheirProtocolErrorAppearancesAndClearArrays() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            for (WrapMode mode : List.of(WrapMode.NULL, WrapMode.WRONG_LENGTH,
                    WrapMode.THROW)) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(fixture.keyWrap, mode);
                RecordingGcm gcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
                AtomicInteger resolverCalls = new AtomicInteger();
                assertCode(
                        ErrorCode.KEY_UNWRAP_FAILED,
                        () -> receiver(fixture, keyWrap, gcm, fixture.ed25519).receive(
                                fixture.signedRequest(wire, kid -> {
                                    resolverCalls.incrementAndGet();
                                    return Optional.of(fixture.trustedSigningKey());
                                }, List.of(fixture.second))
                        )
                );
                assertEquals(0, resolverCalls.get());
                assertEquals(0, gcm.decryptCalls);
                assertTrue(allZero(keyWrap.kek));
                if (keyWrap.output != null) assertTrue(allZero(keyWrap.output));
            }

            for (GcmMode mode : List.of(GcmMode.NULL, GcmMode.THROW)) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(
                        fixture.keyWrap, WrapMode.DELEGATE
                );
                RecordingGcm gcm = new RecordingGcm(fixture.gcm, mode);
                AtomicInteger resolverCalls = new AtomicInteger();
                assertCode(ErrorCode.GCM_AUTH_FAILED, () ->
                        receiver(fixture, keyWrap, gcm, fixture.ed25519).receive(
                                fixture.signedRequest(wire, kid -> {
                                    resolverCalls.incrementAndGet();
                                    return Optional.of(fixture.trustedSigningKey());
                                }, List.of(fixture.second))
                        ));
                assertEquals(0, resolverCalls.get());
                assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad);
                if (gcm.plaintext != null) assertTrue(allZero(gcm.plaintext));
            }
            assertEquals(32, fixture.second.publicKey().length);
        }
    }

    @Test
    void bindingPrecedesResolverAndResolverAndKeyConfusionFailuresAreInternal() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            String badBinding = fixture.signedBindingFailure(wire);
            AtomicInteger resolverCalls = new AtomicInteger();
            RecordingEd25519 verifier = new RecordingEd25519(
                    fixture.ed25519, VerifyMode.DELEGATE
            );
            RecordingKeyWrap bindingWrap = new RecordingKeyWrap(
                    fixture.keyWrap, WrapMode.DELEGATE
            );
            RecordingGcm bindingGcm = new RecordingGcm(
                    fixture.gcm, GcmMode.DELEGATE
            );
            assertCode(ErrorCode.BINDING_FAILED, () -> receiver(
                    fixture, bindingWrap, bindingGcm, verifier
            ).receive(fixture.signedRequest(badBinding, kid -> {
                resolverCalls.incrementAndGet();
                return Optional.of(fixture.trustedSigningKey());
            }, List.of(fixture.second))));
            assertEquals(0, resolverCalls.get());
            assertEquals(0, verifier.verifyCalls);
            assertAllZero(bindingWrap.kek, bindingWrap.output,
                    bindingGcm.key, bindingGcm.aad, bindingGcm.plaintext);

            assertCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.signedReceiver().receive(
                    fixture.signedRequest(wire, kid -> Optional.empty(), List.of(fixture.second))
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                    fixture.signedRequest(wire, kid -> null, List.of(fixture.second))
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                    fixture.signedRequest(wire, kid -> {
                        throw new IllegalStateException("resolver unavailable");
                    }, List.of(fixture.second))
            ));

            byte[] unrelatedPublic = fixture.unrelatedSigning.publicKey();
            try {
                String unrelatedKid = Ed25519KeyId.derive(unrelatedPublic);
                TrustedEd25519Key recordKidMismatch = new TrustedEd25519Key(
                        "other-sender", unrelatedKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                        fixture.signedRequest(wire, kid -> Optional.of(recordKidMismatch),
                                List.of(fixture.second))
                ));
                TrustedEd25519Key actualKeyMismatch = new TrustedEd25519Key(
                        IDENTITY_ID, fixture.signingKid, unrelatedPublic
                );
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                        fixture.signedRequest(wire, kid -> Optional.of(actualKeyMismatch),
                                List.of(fixture.second))
                ));
            } finally {
                clear(unrelatedPublic);
            }
        }
    }

    @Test
    void falseAndThrowingVerificationClearExactSegmentsAndNonCanonicalSegmentsVerifyAsReceived() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            for (VerifyMode mode : List.of(VerifyMode.FALSE, VerifyMode.THROW)) {
                RecordingKeyWrap keyWrap = new RecordingKeyWrap(
                        fixture.keyWrap, WrapMode.DELEGATE
                );
                RecordingGcm gcm = new RecordingGcm(fixture.gcm, GcmMode.DELEGATE);
                RecordingEd25519 verifier = new RecordingEd25519(fixture.ed25519, mode);
                assertCode(mode == VerifyMode.FALSE ? ErrorCode.SIGNATURE_INVALID
                                : ErrorCode.INTERNAL_ERROR,
                        () -> receiver(fixture, keyWrap, gcm, verifier).receive(
                                fixture.signedRequest(wire,
                                        kid -> Optional.of(fixture.trustedSigningKey()),
                                        List.of(fixture.second))
                        ));
                assertEquals(1, verifier.verifyCalls);
                assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad, gcm.plaintext,
                        verifier.publicKey, verifier.message, verifier.signature);
            }

            String nonCanonical = fixture.authenticatedNonCanonicalSignedWire(wire);
            RecordingEd25519 exactVerifier = new RecordingEd25519(
                    fixture.ed25519, VerifyMode.DELEGATE
            );
            ObfuscationX25519SignedReceiver.Result result = receiver(
                    fixture,
                    new RecordingKeyWrap(fixture.keyWrap, WrapMode.DELEGATE),
                    new RecordingGcm(fixture.gcm, GcmMode.DELEGATE),
                    exactVerifier
            ).receive(fixture.signedRequest(
                    nonCanonical,
                    kid -> Optional.of(fixture.trustedSigningKey()),
                    List.of(fixture.second)
            ));
            assertArrayEquals(BINARY, result.payload().data());
            assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                    result.authenticationStatus());
            assertEquals(1, exactVerifier.verifyCalls);
            assertAllZero(exactVerifier.publicKey, exactVerifier.message,
                    exactVerifier.signature);
        }
    }

    @Test
    void requestAllowsNullElementsForRecoveryAndSnapshotsOnlyTheHandleList() {
        try (Fixture fixture = new Fixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver(null, fixture.gcm, fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver(fixture.recovery(), null,
                            fixture.ed25519));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver(fixture.recovery(), fixture.gcm,
                            null));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Request("{}", null, List.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Request("{}",
                            kid -> Optional.empty(), null));
            assertThrows(IllegalArgumentException.class,
                    () -> fixture.signedReceiver().receive(null));

            String wire = fixture.sendSigned(fixture.emptyPayload());
            ArrayList<X25519PrivateKeyHandle> handles = new ArrayList<>();
            handles.add(fixture.first);
            ObfuscationX25519SignedReceiver.Request snapshot =
                    new ObfuscationX25519SignedReceiver.Request(
                            wire, kid -> Optional.of(fixture.trustedSigningKey()), handles
                    );
            handles.clear();
            assertSame(fixture.first, snapshot.recipientPrivateKeys().get(0));
            assertThrows(UnsupportedOperationException.class,
                    () -> snapshot.recipientPrivateKeys().add(fixture.second));
            assertArrayEquals(new byte[0], fixture.signedReceiver().receive(snapshot).payload().data());

            ObfuscationX25519SignedReceiver.Request nullElement =
                    new ObfuscationX25519SignedReceiver.Request(
                            wire, kid -> Optional.of(fixture.trustedSigningKey()),
                            Arrays.asList((X25519PrivateKeyHandle) null)
                    );
            assertCode(ErrorCode.INTERNAL_ERROR,
                    () -> fixture.signedReceiver().receive(nullElement));

            byte[] matchingPublic = fixture.second.publicKey();
            try {
                X25519PrivateKeyHandle foreign = new X25519PrivateKeyHandle() {
                    @Override public byte[] publicKey() { return matchingPublic.clone(); }
                    @Override public void close() { }
                };
                assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                        fixture.signedRequest(wire,
                                kid -> Optional.of(fixture.trustedSigningKey()), List.of(foreign))
                ));
            } finally {
                clear(matchingPublic);
            }
            X25519PrivateKeyHandle closed = fixture.x25519.generatePrivateKey();
            closed.close();
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.signedReceiver().receive(
                    fixture.signedRequest(wire,
                            kid -> Optional.of(fixture.trustedSigningKey()), List.of(closed))
            ));

            ProtocolSenderIdentity identity = new ProtocolSenderIdentity(
                    IDENTITY_ID, fixture.signingKid
            );
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Result(
                            null, MESSAGE_ID, TIMESTAMP,
                            ProtocolAuthenticationStatus.SIGNED_VALID, identity));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Result(
                            fixture.binaryPayload(), null, TIMESTAMP,
                            ProtocolAuthenticationStatus.SIGNED_VALID, identity));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Result(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP,
                            ProtocolAuthenticationStatus.UNSIGNED, identity));
            assertThrows(IllegalArgumentException.class,
                    () -> new ObfuscationX25519SignedReceiver.Result(
                            fixture.binaryPayload(), MESSAGE_ID, TIMESTAMP,
                            ProtocolAuthenticationStatus.SIGNED_VALID, null));
        }
    }

    private static ObfuscationX25519SignedReceiver receiver(
            Fixture fixture,
            A256KeyWrapCrypto keyWrap,
            A256GcmCrypto gcm,
            Ed25519Crypto verifier
    ) {
        return new ObfuscationX25519SignedReceiver(
                new ObfuscationX25519CekRecovery(
                        new ObfuscationX25519KeyDeriver(fixture.x25519, fixture.hkdf), keyWrap
                ), gcm, verifier
        );
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            assertTrue(allZero(value), "receiver-owned provider array was not cleared");
        }
    }

    private enum WrapMode { DELEGATE, THROW, NULL, WRONG_LENGTH }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private final WrapMode mode;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(A256KeyWrapCrypto delegate, WrapMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            return delegate.wrap(kek, keyToWrap);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            this.kek = kek;
            if (mode == WrapMode.THROW) {
                throw new CryptoOperationException("intentional unwrap failure");
            }
            output = mode == WrapMode.NULL ? null
                    : mode == WrapMode.WRONG_LENGTH ? filled(31, 0x45)
                    : delegate.unwrap(kek, wrappedKey);
            return output;
        }
    }

    private enum GcmMode { DELEGATE, THROW, NULL }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final GcmMode mode;
        private int decryptCalls;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(A256GcmCrypto delegate, GcmMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) {
            decryptCalls++;
            this.key = key;
            this.aad = aad;
            if (mode == GcmMode.THROW) {
                throw new CryptoOperationException("intentional GCM failure");
            }
            if (mode == GcmMode.NULL) return null;
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }

    private enum VerifyMode { DELEGATE, FALSE, THROW }

    private static final class RecordingEd25519 implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private final VerifyMode mode;
        private int verifyCalls;
        private byte[] publicKey;
        private byte[] message;
        private byte[] signature;

        private RecordingEd25519(Ed25519Crypto delegate, VerifyMode mode) {
            this.delegate = delegate;
            this.mode = mode;
        }

        @Override public Ed25519PrivateKeyHandle generatePrivateKey() {
            return delegate.generatePrivateKey();
        }
        @Override public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            return delegate.importPrivateKey(privateKey);
        }
        @Override public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            return delegate.sign(privateKey, message);
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            verifyCalls++;
            this.publicKey = publicKey;
            this.message = message;
            this.signature = signature;
            if (mode == VerifyMode.THROW) {
                throw new CryptoOperationException("intentional verification failure");
            }
            if (mode == VerifyMode.FALSE) return false;
            return delegate.verify(publicKey, message, signature);
        }
    }
}
