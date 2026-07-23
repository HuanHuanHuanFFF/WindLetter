package com.windletter.api.impl;

import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.api.model.DecryptRequest;
import com.windletter.api.model.DecryptResult;
import com.windletter.api.model.Payload;
import com.windletter.api.model.SenderIdentity;
import com.windletter.api.spi.DecryptionKeyLease;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientKeyStore;
import com.windletter.api.spi.VerificationKeyMaterial;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.flow.ObfuscationHybridSignedReceiver;
import com.windletter.protocol.flow.ObfuscationHybridUnsignedReceiver;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.routing.ObfuscationHybridCekRecovery;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Obfuscation Hybrid receiver mapping with atomic private-key pairs. */
final class ObfuscationHybridReceiverOrchestrator {

    private final RecipientKeyStore recipientKeys;
    private final IdentityService identities;
    private final ObfuscationHybridUnsignedReceiver unsignedReceiver;
    private final ObfuscationHybridSignedReceiver signedReceiver;

    ObfuscationHybridReceiverOrchestrator(
        RecipientKeyStore recipientKeys,
        IdentityService identities
    ) {
        this.recipientKeys = recipientKeys;
        this.identities = identities;
        ObfuscationHybridKeyDeriver keyDeriver = new ObfuscationHybridKeyDeriver(
            new BouncyCastleX25519Crypto(),
            new BouncyCastleMLKem768Crypto(),
            new BouncyCastleHkdfCrypto()
        );
        ObfuscationHybridCekRecovery cekRecovery = new ObfuscationHybridCekRecovery(
            keyDeriver,
            new BouncyCastleA256KeyWrapCrypto()
        );
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.unsignedReceiver = new ObfuscationHybridUnsignedReceiver(cekRecovery, gcm);
        this.signedReceiver = new ObfuscationHybridSignedReceiver(
            cekRecovery,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
    }

    DecryptResult decrypt(DecryptRequest request, boolean signed) {
        List<DecryptionKeyLease> leases = openRecipientLeases(request);
        Throwable pending = null;
        try {
            List<ObfuscationHybridRecipientPrivateKeys> candidates = validatedCandidates(
                leases
            );
            return signed
                ? receiveSigned(request.wireJson(), candidates)
                : receiveUnsigned(request.wireJson(), candidates);
        } catch (RuntimeException | Error failure) {
            pending = failure;
            throw failure;
        } finally {
            closeAll(leases, pending);
        }
    }

    private DecryptResult receiveUnsigned(
        String wireJson,
        List<ObfuscationHybridRecipientPrivateKeys> candidates
    ) {
        try {
            ObfuscationHybridUnsignedReceiver.Result result = unsignedReceiver.receive(
                new ObfuscationHybridUnsignedReceiver.Request(wireJson, candidates)
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.UNSIGNED) {
                throw new IllegalStateException(
                    "unsigned obfuscation Hybrid flow returned invalid auth status"
                );
            }
            return new DecryptResult(
                DecryptStatus.SUCCESS,
                toApiPayload(result.payload()),
                null,
                VerificationStatus.UNSIGNED,
                null,
                result.messageId(),
                result.timestamp()
            );
        } catch (ProtocolException failure) {
            return mapProtocolFailure(failure);
        }
    }

    private DecryptResult receiveSigned(
        String wireJson,
        List<ObfuscationHybridRecipientPrivateKeys> candidates
    ) {
        TrustedSigningResolver signingResolver = new TrustedSigningResolver(identities);
        try {
            ObfuscationHybridSignedReceiver.Result result = signedReceiver.receive(
                new ObfuscationHybridSignedReceiver.Request(
                    wireJson,
                    signingResolver,
                    candidates
                )
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.SIGNED_VALID) {
                throw new IllegalStateException(
                    "signed obfuscation Hybrid flow returned invalid auth status"
                );
            }
            return new DecryptResult(
                DecryptStatus.SUCCESS,
                toApiPayload(result.payload()),
                signingResolver.authenticatedIdentity(result.authenticatedSender()),
                VerificationStatus.SIGNED_VALID,
                null,
                result.messageId(),
                result.timestamp()
            );
        } catch (ProtocolException failure) {
            return mapProtocolFailure(failure);
        }
    }

    private List<DecryptionKeyLease> openRecipientLeases(DecryptRequest request) {
        List<DecryptionKeyLease> opened = recipientKeys.openAll(request.myIdentity());
        if (opened == null) {
            throw new IllegalStateException("recipient key store returned null");
        }
        return new ArrayList<>(opened);
    }

    private static List<ObfuscationHybridRecipientPrivateKeys> validatedCandidates(
        List<DecryptionKeyLease> leases
    ) {
        List<ObfuscationHybridRecipientPrivateKeys> candidates = new ArrayList<>(
            leases.size()
        );
        Set<RecipientPair> seenPairs = new HashSet<>(leases.size());
        for (DecryptionKeyLease lease : leases) {
            if (lease == null) {
                throw new IllegalStateException("recipient key store returned a null lease");
            }
            X25519PrivateKeyHandle x25519PrivateKey = lease.x25519PrivateKey();
            byte[] x25519PublicKey = x25519PrivateKey.publicKey();
            byte[] mlkem768PublicKey = null;
            try {
                String x25519Kid = X25519KeyId.derive(x25519PublicKey);
                if (!x25519Kid.equals(lease.x25519Kid())) {
                    throw new IllegalStateException(
                        "recipient X25519 lease kid does not match its public key"
                    );
                }

                String mlkem768Kid = lease.mlkem768Kid();
                MLKem768PrivateKeyHandle mlkem768PrivateKey = lease.mlkem768PrivateKey();
                if (mlkem768Kid == null && mlkem768PrivateKey == null) {
                    continue;
                }
                if (mlkem768Kid == null || mlkem768PrivateKey == null) {
                    throw new IllegalStateException(
                        "recipient key store returned an incomplete Hybrid lease"
                    );
                }
                mlkem768PublicKey = mlkem768PrivateKey.publicKey();
                String derivedMlkem768Kid = MLKem768KeyId.derive(mlkem768PublicKey);
                if (!derivedMlkem768Kid.equals(mlkem768Kid)) {
                    throw new IllegalStateException(
                        "recipient ML-KEM lease kid does not match its public key"
                    );
                }
                if (!seenPairs.add(new RecipientPair(x25519Kid, derivedMlkem768Kid))) {
                    throw new IllegalStateException(
                        "recipient key store returned a duplicate Hybrid pair"
                    );
                }
                candidates.add(new ObfuscationHybridRecipientPrivateKeys(
                    x25519PrivateKey,
                    mlkem768PrivateKey
                ));
            } finally {
                clear(x25519PublicKey);
                clear(mlkem768PublicKey);
            }
        }
        return List.copyOf(candidates);
    }

    private static Payload toApiPayload(ProtocolPayload payload) {
        byte[] data = payload.data();
        try {
            return new Payload(payload.contentType(), data, payload.originalSize());
        } finally {
            clear(data);
        }
    }

    private static DecryptResult mapProtocolFailure(ProtocolException failure) {
        if (failure.errorCode() == ErrorCode.INTERNAL_ERROR) {
            throw new IllegalStateException("local Wind Letter receiver operation failed", failure);
        }
        if (failure.errorCode() == ErrorCode.NOT_FOR_ME) {
            return new DecryptResult(
                DecryptStatus.NOT_FOR_ME,
                null,
                null,
                VerificationStatus.NOT_APPLICABLE,
                ErrorCode.NOT_FOR_ME,
                null,
                null
            );
        }
        return new DecryptResult(
            DecryptStatus.INVALID_MESSAGE,
            null,
            null,
            VerificationStatus.FAILED,
            ErrorCode.INVALID_MESSAGE,
            null,
            null
        );
    }

    private static void closeAll(List<DecryptionKeyLease> leases, Throwable pending) {
        Throwable closeFailure = null;
        for (int i = leases.size() - 1; i >= 0; i--) {
            DecryptionKeyLease lease = leases.get(i);
            if (lease == null) {
                continue;
            }
            try {
                lease.close();
            } catch (RuntimeException | Error failure) {
                if (closeFailure == null) {
                    closeFailure = failure;
                } else {
                    closeFailure.addSuppressed(failure);
                }
            }
        }
        if (closeFailure == null) {
            return;
        }
        if (pending != null) {
            pending.addSuppressed(closeFailure);
            return;
        }
        if (closeFailure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        throw (Error) closeFailure;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record RecipientPair(String x25519Kid, String mlkem768Kid) {
    }

    private static final class TrustedSigningResolver implements Ed25519VerificationKeyResolver {

        private final IdentityService identities;
        private SenderIdentity resolvedIdentity;

        private TrustedSigningResolver(IdentityService identities) {
            this.identities = identities;
        }

        @Override
        public Optional<TrustedEd25519Key> resolve(String expectedKid) {
            Optional<VerificationKeyMaterial> verification = identities.resolveVerificationKeyByKid(
                expectedKid
            );
            if (verification == null) {
                throw new IllegalStateException(
                    "identity service returned null verification result"
                );
            }
            if (verification.isEmpty()) {
                return Optional.empty();
            }
            VerificationKeyMaterial material = verification.get();
            byte[] publicKey = material.ed25519PublicKey();
            try {
                String derivedKid = Ed25519KeyId.derive(publicKey);
                if (!expectedKid.equals(material.signingKid())
                    || !expectedKid.equals(derivedKid)) {
                    throw new IllegalStateException(
                        "verification key record does not match the requested kid"
                    );
                }
                Optional<SenderIdentity> identity = identities.resolveSenderBySigningKid(expectedKid);
                if (identity == null) {
                    throw new IllegalStateException(
                        "identity service returned null sender result"
                    );
                }
                SenderIdentity senderIdentity = identity.orElseThrow(
                    () -> new IllegalStateException(
                        "verified signing key has no trusted sender identity"
                    )
                );
                if (!expectedKid.equals(senderIdentity.signingKid())) {
                    throw new IllegalStateException(
                        "sender identity does not match the requested signing kid"
                    );
                }
                if (resolvedIdentity != null && !resolvedIdentity.equals(senderIdentity)) {
                    throw new IllegalStateException(
                        "identity service returned inconsistent sender identities"
                    );
                }
                resolvedIdentity = senderIdentity;
                return Optional.of(new TrustedEd25519Key(
                    senderIdentity.senderId(),
                    expectedKid,
                    publicKey
                ));
            } finally {
                clear(publicKey);
            }
        }

        private SenderIdentity authenticatedIdentity(ProtocolSenderIdentity authenticated) {
            if (resolvedIdentity == null
                || !resolvedIdentity.senderId().equals(authenticated.identityId())
                || !resolvedIdentity.signingKid().equals(authenticated.signingKid())) {
                throw new IllegalStateException(
                    "signed flow identity does not match the trusted identity record"
                );
            }
            return resolvedIdentity;
        }
    }
}
