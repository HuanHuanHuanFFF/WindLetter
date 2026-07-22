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
import com.windletter.api.spi.SenderPublicKeyResolver;
import com.windletter.api.spi.VerificationKeyMaterial;
import com.windletter.api.spi.X25519PublicKeyMaterial;
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
import com.windletter.protocol.flow.PublicHybridSignedReceiver;
import com.windletter.protocol.flow.PublicHybridUnsignedReceiver;
import com.windletter.protocol.flow.SenderX25519PublicKeyResolver;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.routing.PublicHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Public X25519/ML-KEM-768 receiver mapping kept local to the API facade. */
final class PublicHybridReceiverOrchestrator {

    private final RecipientKeyStore recipientKeys;
    private final SenderPublicKeyResolver senderKeys;
    private final IdentityService identities;
    private final PublicHybridUnsignedReceiver unsignedReceiver;
    private final PublicHybridSignedReceiver signedReceiver;

    PublicHybridReceiverOrchestrator(
        RecipientKeyStore recipientKeys,
        SenderPublicKeyResolver senderKeys,
        IdentityService identities
    ) {
        this.recipientKeys = recipientKeys;
        this.senderKeys = senderKeys;
        this.identities = identities;
        PublicHybridKekDeriver kekDeriver = new PublicHybridKekDeriver(
            new BouncyCastleX25519Crypto(),
            new BouncyCastleMLKem768Crypto(),
            new BouncyCastleHkdfCrypto()
        );
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.unsignedReceiver = new PublicHybridUnsignedReceiver(kekDeriver, keyWrap, gcm);
        this.signedReceiver = new PublicHybridSignedReceiver(
            kekDeriver,
            keyWrap,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
    }

    DecryptResult decrypt(DecryptRequest request, boolean signed) {
        List<DecryptionKeyLease> leases = openRecipientLeases(request);
        Throwable pending = null;
        try {
            List<PublicHybridRecipientPrivateKeys> candidates = validatedCandidates(leases);
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
        List<PublicHybridRecipientPrivateKeys> candidates
    ) {
        try {
            PublicHybridUnsignedReceiver.Result result = unsignedReceiver.receive(
                new PublicHybridUnsignedReceiver.Request(
                    wireJson,
                    senderX25519Resolver(),
                    candidates
                )
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.UNSIGNED) {
                throw new IllegalStateException("unsigned Hybrid flow returned invalid auth status");
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
        List<PublicHybridRecipientPrivateKeys> candidates
    ) {
        TrustedSigningResolver signingResolver = new TrustedSigningResolver(identities);
        try {
            PublicHybridSignedReceiver.Result result = signedReceiver.receive(
                new PublicHybridSignedReceiver.Request(
                    wireJson,
                    senderX25519Resolver(),
                    signingResolver,
                    candidates
                )
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.SIGNED_VALID) {
                throw new IllegalStateException("signed Hybrid flow returned invalid auth status");
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

    private static List<PublicHybridRecipientPrivateKeys> validatedCandidates(
        List<DecryptionKeyLease> leases
    ) {
        List<PublicHybridRecipientPrivateKeys> candidates = new ArrayList<>(leases.size());
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
                candidates.add(new PublicHybridRecipientPrivateKeys(
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

    private SenderX25519PublicKeyResolver senderX25519Resolver() {
        return expectedKid -> {
            Optional<X25519PublicKeyMaterial> resolved = senderKeys.resolveX25519ByKid(expectedKid);
            if (resolved == null) {
                throw new IllegalStateException("sender public-key resolver returned null");
            }
            if (resolved.isEmpty()) {
                return Optional.empty();
            }
            X25519PublicKeyMaterial material = resolved.get();
            byte[] publicKey = material.publicKey();
            String derivedKid = X25519KeyId.derive(publicKey);
            if (!expectedKid.equals(material.kid()) || !expectedKid.equals(derivedKid)) {
                clear(publicKey);
                throw new IllegalStateException(
                    "sender X25519 key record does not match the requested kid"
                );
            }
            return Optional.of(publicKey);
        };
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
                throw new IllegalStateException("identity service returned null verification result");
            }
            if (verification.isEmpty()) {
                return Optional.empty();
            }
            VerificationKeyMaterial material = verification.get();
            byte[] publicKey = material.ed25519PublicKey();
            try {
                String derivedKid = Ed25519KeyId.derive(publicKey);
                if (!expectedKid.equals(material.signingKid()) || !expectedKid.equals(derivedKid)) {
                    throw new IllegalStateException(
                        "verification key record does not match the requested kid"
                    );
                }
                Optional<SenderIdentity> identity = identities.resolveSenderBySigningKid(expectedKid);
                if (identity == null) {
                    throw new IllegalStateException("identity service returned null sender result");
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
