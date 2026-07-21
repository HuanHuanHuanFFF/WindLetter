package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.TrustedEd25519Key;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationHybridSignedReceiverTest {

    @Test
    void verifiesExactReceivedSegmentsAndReturnsIdentityOnlyAfterBinding() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            RecordingVerifier verifier = new RecordingVerifier(fixture.ed25519);
            ObfuscationHybridSignedReceiver receiver =
                    new ObfuscationHybridSignedReceiver(
                            fixture.recovery(), fixture.gcm, verifier
                    );

            ObfuscationHybridSignedReceiver.Result result = receiver.receive(
                    fixture.signedRequest(
                            wire,
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    )
            );
            assertArrayEquals(
                    ProtocolFlowTestFixtures.BINARY_PAYLOAD, result.payload().data()
            );
            assertEquals(
                    ProtocolAuthenticationStatus.SIGNED_VALID,
                    result.authenticationStatus()
            );
            assertEquals(
                    ObfuscationHybridFlowTestFixtures.IDENTITY_ID,
                    result.authenticatedSender().identityId()
            );
            assertEquals(fixture.signingKid,
                    result.authenticatedSender().signingKid());
            assertEquals(1, verifier.verifyCalls);
            assertAllZero(verifier.publicKey, verifier.message, verifier.signature);

            AtomicInteger bindingResolverCalls = new AtomicInteger();
            assertProtocolCode(ErrorCode.BINDING_FAILED, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedSignedWrongBinding(
                                    wire, fixture.middle
                            ),
                            kid -> {
                                bindingResolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.middle.privateKeys())
                    ))
            );
            assertEquals(0, bindingResolverCalls.get());

            String nonCanonical = fixture.authenticatedNonCanonicalSignedWire(
                    wire, fixture.middle
            );
            assertEquals(
                    ProtocolAuthenticationStatus.SIGNED_VALID,
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            nonCanonical,
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    )).authenticationStatus()
            );
        }
    }

    @Test
    void rejectsUnknownFlippedAndMismatchedTrustedSigningKeys() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());

            assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedFlippedSignature(
                                    wire, fixture.middle
                            ),
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    ))
            );
            assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedUnknownSigner(wire, fixture.middle),
                            fixture.trustedSigningResolver(),
                            List.of(fixture.middle.privateKeys())
                    ))
            );

            byte[] unrelatedPublic = fixture.unrelatedSigning.publicKey();
            try {
                TrustedEd25519Key mismatchedRecordKid = new TrustedEd25519Key(
                        "other-identity",
                        fixture.unrelatedSigningKid,
                        unrelatedPublic
                );
                RecordingVerifier recordMismatchVerifier =
                        new RecordingVerifier(fixture.ed25519);
                assertProtocolCode(ErrorCode.INTERNAL_ERROR, () ->
                        new ObfuscationHybridSignedReceiver(
                                fixture.recovery(),
                                fixture.gcm,
                                recordMismatchVerifier
                        ).receive(fixture.signedRequest(
                                    wire,
                                    kid -> Optional.of(mismatchedRecordKid),
                                    List.of(fixture.middle.privateKeys())
                                ))
                );
                assertEquals(0, recordMismatchVerifier.verifyCalls);
                TrustedEd25519Key mismatchedActualKey = new TrustedEd25519Key(
                        ObfuscationHybridFlowTestFixtures.IDENTITY_ID,
                        fixture.signingKid,
                        unrelatedPublic
                );
                assertProtocolCode(ErrorCode.INTERNAL_ERROR, () ->
                        fixture.signedReceiver().receive(fixture.signedRequest(
                                wire,
                                kid -> Optional.of(mismatchedActualKey),
                                List.of(fixture.middle.privateKeys())
                        ))
                );

                TrustedEd25519Key unrelatedTrustedKey = new TrustedEd25519Key(
                        "unrelated-identity",
                        fixture.unrelatedSigningKid,
                        unrelatedPublic
                );
                RecordingVerifier wrongKeyVerifier =
                        new RecordingVerifier(fixture.ed25519);
                assertProtocolCode(ErrorCode.SIGNATURE_INVALID, () ->
                        new ObfuscationHybridSignedReceiver(
                                fixture.recovery(), fixture.gcm, wrongKeyVerifier
                        ).receive(fixture.signedRequest(
                                fixture.authenticatedWrongKeySignature(
                                        wire, fixture.middle
                                ),
                                kid -> Optional.of(unrelatedTrustedKey),
                                List.of(fixture.middle.privateKeys())
                        ))
                );
                assertEquals(1, wrongKeyVerifier.verifyCalls);
                assertAllZero(
                        wrongKeyVerifier.publicKey,
                        wrongKeyVerifier.message,
                        wrongKeyVerifier.signature
                );
            } finally {
                ObfuscationHybridFlowTestFixtures.clear(unrelatedPublic);
            }
        }
    }

    @Test
    void recoveryRunsBeforeSignerLookupAndRequestDefersLocalPairValidation() {
        try (ObfuscationHybridFlowTestFixtures fixture =
                     new ObfuscationHybridFlowTestFixtures()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            AtomicInteger resolverCalls = new AtomicInteger();
            assertProtocolCode(ErrorCode.NOT_FOR_ME, () ->
                    fixture.signedReceiver().receive(fixture.signedRequest(
                            wire,
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.trustedSigningKey());
                            },
                            List.of(fixture.unrelated.privateKeys())
                    ))
            );
            assertEquals(0, resolverCalls.get());

            ObfuscationHybridSignedReceiver.Request poisoned =
                    new ObfuscationHybridSignedReceiver.Request(
                            wire,
                            fixture.trustedSigningResolver(),
                            Arrays.asList(
                                    (ObfuscationHybridRecipientPrivateKeys) null
                            )
                    );
            assertProtocolCode(
                    ErrorCode.INTERNAL_ERROR,
                    () -> fixture.signedReceiver().receive(poisoned)
            );
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridSignedReceiver(
                            null, fixture.gcm, fixture.ed25519
                    ));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridSignedReceiver(
                            fixture.recovery(), null, fixture.ed25519
                    ));
            assertThrows(IllegalArgumentException.class, () ->
                    new ObfuscationHybridSignedReceiver(
                            fixture.recovery(), fixture.gcm, null
                    ));
        }
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            for (byte current : value) assertEquals(0, current);
        }
    }

    private static final class RecordingVerifier implements Ed25519Crypto {
        private final Ed25519Crypto delegate;
        private int verifyCalls;
        private byte[] publicKey;
        private byte[] message;
        private byte[] signature;

        private RecordingVerifier(Ed25519Crypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public Ed25519PrivateKeyHandle generatePrivateKey() {
            return delegate.generatePrivateKey();
        }

        @Override
        public Ed25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            return delegate.importPrivateKey(privateKey);
        }

        @Override
        public byte[] sign(Ed25519PrivateKeyHandle privateKey, byte[] message) {
            return delegate.sign(privateKey, message);
        }

        @Override
        public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            verifyCalls++;
            this.publicKey = publicKey;
            this.message = message;
            this.signature = signature;
            return delegate.verify(publicKey, message, signature);
        }
    }
}
