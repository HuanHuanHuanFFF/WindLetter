package com.windletter.api.impl;

import com.windletter.api.WindLetterReceiver;
import com.windletter.armor.ArmorException;
import com.windletter.armor.WindLetterArmor;
import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.VerificationPolicy;
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
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.flow.PublicX25519SignedReceiver;
import com.windletter.protocol.flow.PublicX25519UnsignedReceiver;
import com.windletter.protocol.flow.SenderX25519PublicKeyResolver;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.WindLetter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Default receiver facade backed by strict production Wind Letter protocol flows. */
public final class DefaultWindLetterReceiver implements WindLetterReceiver {

    private final RecipientKeyStore recipientKeys;
    private final SenderPublicKeyResolver senderKeys;
    private final IdentityService identities;
    private final JacksonOuterWireParser parser = new JacksonOuterWireParser();
    private final PublicX25519UnsignedReceiver publicX25519Unsigned;
    private final PublicX25519SignedReceiver publicX25519Signed;
    private final PublicHybridReceiverOrchestrator publicHybrid;
    private final ObfuscationX25519ReceiverOrchestrator obfuscationX25519;
    private final ObfuscationHybridReceiverOrchestrator obfuscationHybrid;

    public DefaultWindLetterReceiver(
        RecipientKeyStore recipientKeys,
        SenderPublicKeyResolver senderKeys,
        IdentityService identities
    ) {
        this.recipientKeys = requireDependency(recipientKeys, "recipientKeys");
        this.senderKeys = requireDependency(senderKeys, "senderKeys");
        this.identities = requireDependency(identities, "identities");

        PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(
            new BouncyCastleX25519Crypto(),
            new BouncyCastleHkdfCrypto()
        );
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.publicX25519Unsigned = new PublicX25519UnsignedReceiver(kekDeriver, keyWrap, gcm);
        this.publicX25519Signed = new PublicX25519SignedReceiver(
            kekDeriver,
            keyWrap,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
        this.publicHybrid = new PublicHybridReceiverOrchestrator(
            recipientKeys,
            senderKeys,
            identities
        );
        this.obfuscationX25519 = new ObfuscationX25519ReceiverOrchestrator(
            recipientKeys,
            identities
        );
        this.obfuscationHybrid = new ObfuscationHybridReceiverOrchestrator(
            recipientKeys,
            identities
        );
    }

    @Override
    public DecryptResult decrypt(DecryptRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return decryptWithPolicy(request, request.verificationPolicy());
    }

    @Override
    public DecryptResult decryptAndVerify(DecryptRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return decryptWithPolicy(request, VerificationPolicy.REQUIRE_SIGNED_VALID);
    }

    private DecryptResult decryptWithPolicy(
        DecryptRequest request,
        VerificationPolicy verificationPolicy
    ) {
        final DecryptRequest rawRequest;
        try {
            rawRequest = normalizedRawRequest(request);
        } catch (ArmorException failure) {
            return invalidMessage();
        }

        final WindLetter parsed;
        try {
            parsed = parser.parse(rawRequest.wireJson());
        } catch (ProtocolException failure) {
            return mapProtocolFailure(failure);
        }

        ProtectedHeader header = parsed.protectedHeader();
        boolean publicMode = "public".equals(header.windMode());
        boolean obfuscationMode = "obfuscation".equals(header.windMode());
        boolean x25519Profile = "X25519".equals(header.keyAlg());
        boolean hybridProfile = "X25519ML-KEM-768".equals(header.keyAlg());
        boolean signed = "wind+jws".equals(header.cty());
        boolean unsigned = "wind+inner".equals(header.cty());
        if ((!publicMode && !obfuscationMode)
            || (!x25519Profile && !hybridProfile)
            || (!signed && !unsigned)) {
            return invalidMessage();
        }
        if (unsigned && verificationPolicy == VerificationPolicy.REQUIRE_SIGNED_VALID) {
            return invalidMessage();
        }
        if (obfuscationMode) {
            return x25519Profile
                ? obfuscationX25519.decrypt(rawRequest, signed)
                : obfuscationHybrid.decrypt(rawRequest, signed);
        }
        if (hybridProfile) {
            return publicHybrid.decrypt(rawRequest, signed);
        }

        List<DecryptionKeyLease> leases = openRecipientLeases(rawRequest);
        Throwable pending = null;
        try {
            List<X25519PrivateKeyHandle> candidates = validatedX25519Candidates(leases);
            if (signed) {
                return receiveSigned(rawRequest.wireJson(), candidates);
            }
            return receiveUnsigned(rawRequest.wireJson(), candidates);
        } catch (RuntimeException | Error failure) {
            pending = failure;
            throw failure;
        } finally {
            closeAll(leases, pending);
        }
    }

    private DecryptResult receiveUnsigned(
        String wireJson,
        List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        try {
            PublicX25519UnsignedReceiver.Result result = publicX25519Unsigned.receive(
                new PublicX25519UnsignedReceiver.Request(
                    wireJson,
                    senderX25519Resolver(),
                    recipientPrivateKeys
                )
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.UNSIGNED) {
                throw new IllegalStateException("unsigned flow returned an invalid authentication status");
            }
            return unsignedSuccess(result.payload(), result.messageId(), result.timestamp());
        } catch (ProtocolException failure) {
            return mapProtocolFailure(failure);
        }
    }

    private DecryptResult receiveSigned(
        String wireJson,
        List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        TrustedSigningResolver signingResolver = new TrustedSigningResolver(identities);
        try {
            PublicX25519SignedReceiver.Result result = publicX25519Signed.receive(
                new PublicX25519SignedReceiver.Request(
                    wireJson,
                    senderX25519Resolver(),
                    signingResolver,
                    recipientPrivateKeys
                )
            );
            if (result.authenticationStatus() != ProtocolAuthenticationStatus.SIGNED_VALID) {
                throw new IllegalStateException("signed flow returned an invalid authentication status");
            }
            SenderIdentity identity = signingResolver.authenticatedIdentity(result.authenticatedSender());
            return signedSuccess(
                result.payload(),
                result.messageId(),
                result.timestamp(),
                identity
            );
        } catch (ProtocolException failure) {
            return mapProtocolFailure(failure);
        }
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

    private List<DecryptionKeyLease> openRecipientLeases(DecryptRequest request) {
        List<DecryptionKeyLease> opened = recipientKeys.openAll(request.myIdentity());
        if (opened == null) {
            throw new IllegalStateException("recipient key store returned null");
        }
        return new ArrayList<>(opened);
    }

    private static List<X25519PrivateKeyHandle> validatedX25519Candidates(
        List<DecryptionKeyLease> leases
    ) {
        List<X25519PrivateKeyHandle> candidates = new ArrayList<>(leases.size());
        Set<String> seenKids = new HashSet<>(leases.size());
        for (DecryptionKeyLease lease : leases) {
            if (lease == null) {
                throw new IllegalStateException("recipient key store returned a null lease");
            }
            X25519PrivateKeyHandle handle = lease.x25519PrivateKey();
            byte[] publicKey = handle.publicKey();
            try {
                String derivedKid = X25519KeyId.derive(publicKey);
                if (!derivedKid.equals(lease.x25519Kid())) {
                    throw new IllegalStateException(
                        "recipient X25519 lease kid does not match its public key"
                    );
                }
                if (!seenKids.add(derivedKid)) {
                    throw new IllegalStateException("recipient key store returned duplicate X25519 keys");
                }
                candidates.add(handle);
            } finally {
                clear(publicKey);
            }
        }
        return List.copyOf(candidates);
    }

    private static DecryptResult unsignedSuccess(
        ProtocolPayload protocolPayload,
        String messageId,
        long timestamp
    ) {
        return new DecryptResult(
            DecryptStatus.SUCCESS,
            toApiPayload(protocolPayload),
            null,
            VerificationStatus.UNSIGNED,
            null,
            messageId,
            timestamp
        );
    }

    private static DecryptResult signedSuccess(
        ProtocolPayload protocolPayload,
        String messageId,
        long timestamp,
        SenderIdentity senderIdentity
    ) {
        return new DecryptResult(
            DecryptStatus.SUCCESS,
            toApiPayload(protocolPayload),
            senderIdentity,
            VerificationStatus.SIGNED_VALID,
            null,
            messageId,
            timestamp
        );
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
        return invalidMessage();
    }

    private static DecryptResult invalidMessage() {
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

    private static DecryptRequest normalizedRawRequest(DecryptRequest request) {
        if (request.armorFormat() == ArmorFormat.NONE) {
            return request;
        }

        byte[] wireJsonUtf8;
        if (request.armorFormat() == null) {
            wireJsonUtf8 = WindLetterArmor.decodeTextAuto(request.armor());
        } else if (request.armorFormat() == ArmorFormat.BINARY) {
            byte[] binaryArmor = request.armorBytes();
            try {
                wireJsonUtf8 = WindLetterArmor.decodeBinary(binaryArmor);
            } finally {
                clear(binaryArmor);
            }
        } else if (request.armorFormat() == ArmorFormat.BASE64URL) {
            wireJsonUtf8 = WindLetterArmor.decodeBase64Url(request.armor());
        } else {
            wireJsonUtf8 = WindLetterArmor.decodeWindBase1024F(request.armor());
        }

        try {
            return new DecryptRequest(
                new String(wireJsonUtf8, StandardCharsets.UTF_8),
                null,
                null,
                ArmorFormat.NONE,
                request.myIdentity(),
                request.verificationPolicy()
            );
        } finally {
            clear(wireJsonUtf8);
        }
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

    private static <T> T requireDependency(T value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
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
