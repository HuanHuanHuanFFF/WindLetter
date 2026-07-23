package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicHybridTamperE2ETest {

    @Test
    void unrelatedRealMlkemEncapsulationUsesTheSameGenericRecoveryErrorForBothProfiles() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String unsignedWire = fixture.sendUnsigned(fixture.binaryPayload());
            String signedWire = fixture.sendSigned(fixture.binaryPayload());

            String maliciousUnsigned = fixture.replaceTargetEkWithUnrelatedRealEncapsulation(
                    unsignedWire, 1
            );
            assertGenericKeyRecovery(() -> fixture.unsignedReceiver().receive(
                    fixture.unsignedRequest(maliciousUnsigned, fixture.middle)
            ));

            String maliciousSigned = fixture.replaceTargetEkWithUnrelatedRealEncapsulation(
                    signedWire, 1
            );
            assertSignedGenericKeyRecovery(fixture, maliciousSigned);
            assertPairOpen(fixture.middle);
        }
    }

    @Test
    void swappingTwoRealEncapsulationsUsesTheSameGenericRecoveryErrorForBothProfiles() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String unsignedWire = fixture.sendUnsigned(fixture.binaryPayload());
            String signedWire = fixture.sendSigned(fixture.binaryPayload());

            String maliciousUnsigned = fixture.swapRealEncapsulations(
                    unsignedWire, 0, 1
            );
            assertGenericKeyRecovery(() -> fixture.unsignedReceiver().receive(
                    fixture.unsignedRequest(maliciousUnsigned, fixture.middle)
            ));

            String maliciousSigned = fixture.swapRealEncapsulations(signedWire, 0, 1);
            assertSignedGenericKeyRecovery(fixture, maliciousSigned);
            assertPairOpen(fixture.middle);
        }
    }

    @Test
    void actualCekAndGcmReencryptionReachBindingBeforeSignedTrustOrVerification() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String unsignedWire = fixture.sendUnsigned(fixture.binaryPayload());
            String maliciousUnsigned = fixture.authenticatedUnsignedWrongBinding(
                    unsignedWire, fixture.middle, 1
            );
            assertProtocolCode(ErrorCode.BINDING_FAILED,
                    () -> fixture.unsignedReceiver().receive(
                            fixture.unsignedRequest(maliciousUnsigned, fixture.middle)
                    ));

            String signedWire = fixture.sendSigned(fixture.binaryPayload());
            String maliciousSigned = fixture.authenticatedSignedWrongBinding(
                    signedWire, fixture.middle, 1
            );
            AtomicInteger signingResolverCalls = new AtomicInteger();
            CountingEd25519 verifier = new CountingEd25519(fixture.ed25519);
            assertProtocolCode(ErrorCode.BINDING_FAILED,
                    () -> fixture.signedReceiver(verifier).receive(
                            fixture.signedRequest(
                                    maliciousSigned,
                                    fixture.middle,
                                    kid -> {
                                        signingResolverCalls.incrementAndGet();
                                        return Optional.of(fixture.trustedSigningKey());
                                    }
                            )
                    ));
            assertEquals(0, signingResolverCalls.get());
            assertEquals(0, verifier.verifyCalls);
            assertPairOpen(fixture.middle);
        }
    }

    @Test
    void authenticatedSignedMutationsReachExactSignatureAndTrustBoundaries() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());

            assertProtocolCode(ErrorCode.SIGNATURE_INVALID,
                    () -> fixture.signedReceiver().receive(fixture.signedRequest(
                            fixture.authenticatedFlippedSignature(
                                    wire, fixture.middle, 1
                            ),
                            fixture.middle
                    )));

            AtomicInteger resolverCalls = new AtomicInteger();
            AtomicReference<String> requestedKid = new AtomicReference<>();
            CountingEd25519 unknownVerifier = new CountingEd25519(fixture.ed25519);
            String unknownSigner = fixture.authenticatedUnknownRealSigner(
                    wire, fixture.middle, 1
            );
            assertProtocolCode(ErrorCode.SIGNATURE_INVALID,
                    () -> fixture.signedReceiver(unknownVerifier).receive(
                            fixture.signedRequest(unknownSigner, fixture.middle, kid -> {
                                resolverCalls.incrementAndGet();
                                requestedKid.set(kid);
                                return Optional.empty();
                            })
                    ));
            assertEquals(1, resolverCalls.get());
            assertEquals(fixture.unrelatedSigningKid, requestedKid.get());
            assertEquals(0, unknownVerifier.verifyCalls);

            for (String segment : new String[]{"protected", "payload"}) {
                String malicious = fixture.authenticatedChangedSignedSegment(
                        wire, fixture.middle, 1, segment
                );
                assertProtocolCode(ErrorCode.SIGNATURE_INVALID,
                        () -> fixture.signedReceiver().receive(
                                fixture.signedRequest(malicious, fixture.middle)
                        ));
            }
            assertPairOpen(fixture.middle);
        }
    }

    private static void assertSignedGenericKeyRecovery(
            PublicHybridFlowTestFixtures fixture,
            String maliciousWire
    ) {
        AtomicInteger signingResolverCalls = new AtomicInteger();
        assertGenericKeyRecovery(() -> fixture.signedReceiver().receive(
                fixture.signedRequest(maliciousWire, fixture.middle, kid -> {
                    signingResolverCalls.incrementAndGet();
                    return Optional.of(fixture.trustedSigningKey());
                })
        ));
        assertEquals(0, signingResolverCalls.get());
    }

    private static ProtocolException assertGenericKeyRecovery(Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(ErrorCode.KEY_UNWRAP_FAILED, failure.errorCode());
        assertEquals("hybrid recipient key recovery failed", failure.getMessage());
        assertNull(failure.getCause());
        return failure;
    }

    private static void assertPairOpen(PublicHybridFlowTestFixtures.HybridPair pair) {
        byte[] x25519Public = pair.x25519.publicKey();
        byte[] mlkemPublic = pair.mlkem768.publicKey();
        try {
            assertEquals(32, x25519Public.length);
            assertEquals(1184, mlkemPublic.length);
        } finally {
            PublicHybridFlowTestFixtures.clear(x25519Public);
            PublicHybridFlowTestFixtures.clear(mlkemPublic);
        }
    }

    private static final class CountingEd25519 implements Ed25519Crypto {

        private final Ed25519Crypto delegate;
        private int verifyCalls;

        private CountingEd25519(Ed25519Crypto delegate) {
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
            return delegate.verify(publicKey, message, signature);
        }
    }
}
