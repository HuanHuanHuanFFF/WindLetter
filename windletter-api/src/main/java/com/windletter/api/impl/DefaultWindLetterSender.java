package com.windletter.api.impl;

import com.windletter.api.WindLetterSender;
import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;
import com.windletter.api.model.EncryptAndSignRequest;
import com.windletter.api.model.EncryptRequest;
import com.windletter.api.model.EncryptedMessage;
import com.windletter.api.model.Payload;
import com.windletter.api.model.RecipientRef;
import com.windletter.api.model.SigningIdentityRef;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientPublicKeyMaterial;
import com.windletter.api.spi.RecipientPublicKeyResolver;
import com.windletter.api.spi.SenderEncryptionKeyLease;
import com.windletter.api.spi.SenderEncryptionKeyStore;
import com.windletter.api.spi.SigningIdentityLease;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.flow.PublicX25519SignedSender;
import com.windletter.protocol.flow.PublicX25519UnsignedSender;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Default sender facade backed by the production Wind Letter protocol flows. */
public final class DefaultWindLetterSender implements WindLetterSender {

    private final RecipientPublicKeyResolver recipientKeys;
    private final SenderEncryptionKeyStore senderEncryptionKeys;
    private final IdentityService identities;
    private final PublicX25519UnsignedSender publicX25519Unsigned;
    private final PublicX25519SignedSender publicX25519Signed;

    public DefaultWindLetterSender(
        RecipientPublicKeyResolver recipientKeys,
        SenderEncryptionKeyStore senderEncryptionKeys,
        IdentityService identities
    ) {
        this.recipientKeys = requireDependency(recipientKeys, "recipientKeys");
        this.senderEncryptionKeys = requireDependency(senderEncryptionKeys, "senderEncryptionKeys");
        this.identities = requireDependency(identities, "identities");

        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(
            x25519,
            new BouncyCastleHkdfCrypto()
        );
        PublicX25519RecipientBuilder recipientBuilder = new PublicX25519RecipientBuilder(
            kekDeriver,
            new BouncyCastleA256KeyWrapCrypto()
        );
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.publicX25519Unsigned = new PublicX25519UnsignedSender(recipientBuilder, gcm);
        this.publicX25519Signed = new PublicX25519SignedSender(
            recipientBuilder,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
    }

    @Override
    public EncryptedMessage encrypt(EncryptRequest request) {
        requireRequest(request);
        requireRawWire(request.armorFormat(), request.customHeaders());
        requirePublicX25519(request.mode(), request.keyAlgProfile());

        List<byte[]> recipientPublicKeys = resolveX25519Recipients(request.recipients());
        try (SenderEncryptionKeyLease senderLease = openSenderEncryption(
            request.senderEncryptionIdentity()
        )) {
            X25519PrivateKeyHandle senderPrivateKey = validatedSenderEncryptionKey(senderLease);
            ProtocolPayload payload = toProtocolPayload(request.payload());
            PublicX25519UnsignedSender.Result result = publicX25519Unsigned.send(
                new PublicX25519UnsignedSender.Request(
                    payload,
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    senderPrivateKey,
                    recipientPublicKeys
                )
            );
            return rawMessage(result.wireJson());
        } finally {
            clearAll(recipientPublicKeys);
        }
    }

    @Override
    public EncryptedMessage encryptAndSign(EncryptAndSignRequest request) {
        requireRequest(request);
        requireRawWire(request.armorFormat(), request.customHeaders());
        requirePublicX25519(request.mode(), request.keyAlgProfile());

        List<byte[]> recipientPublicKeys = resolveX25519Recipients(request.recipients());
        try (
            SenderEncryptionKeyLease senderLease = openSenderEncryption(
                request.senderEncryptionIdentity()
            );
            SigningIdentityLease signingLease = openSigningIdentity(request.senderSigningIdentity())
        ) {
            X25519PrivateKeyHandle senderPrivateKey = validatedSenderEncryptionKey(senderLease);
            Ed25519PrivateKeyHandle signingPrivateKey = validatedSigningKey(
                request.senderSigningIdentity(),
                signingLease
            );
            ProtocolPayload payload = toProtocolPayload(request.payload());
            PublicX25519SignedSender.Result result = publicX25519Signed.send(
                new PublicX25519SignedSender.Request(
                    payload,
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    senderPrivateKey,
                    signingPrivateKey,
                    recipientPublicKeys
                )
            );
            return rawMessage(result.wireJson());
        } finally {
            clearAll(recipientPublicKeys);
        }
    }

    private List<byte[]> resolveX25519Recipients(List<RecipientRef> recipients) {
        if (recipients.size() > 32) {
            throw new IllegalArgumentException("recipients must contain at most 32 entries");
        }

        List<byte[]> publicKeys = new ArrayList<>(recipients.size());
        Set<String> seenKids = new HashSet<>(recipients.size());
        try {
            for (RecipientRef recipient : recipients) {
                if (isBlank(recipient.x25519Kid())) {
                    throw new IllegalArgumentException(
                        "each X25519 recipient must provide x25519Kid"
                    );
                }
                Optional<RecipientPublicKeyMaterial> resolved = recipientKeys.resolve(recipient);
                if (resolved == null) {
                    throw new IllegalStateException("recipient key resolver returned null");
                }
                RecipientPublicKeyMaterial material = resolved.orElseThrow(
                    () -> new IllegalStateException("recipient public key was not found")
                );
                byte[] publicKey = material.x25519PublicKey();
                String derivedKid = X25519KeyId.derive(publicKey);
                if (!derivedKid.equals(material.x25519Kid())) {
                    clear(publicKey);
                    throw new IllegalStateException(
                        "recipient X25519 key record does not match its public key"
                    );
                }
                if (!derivedKid.equals(recipient.x25519Kid())) {
                    clear(publicKey);
                    throw new IllegalArgumentException(
                        "recipient x25519Kid does not match the resolved public key"
                    );
                }
                if (!isBlank(recipient.mlkem768Kid())
                    && !recipient.mlkem768Kid().equals(material.mlkem768Kid())) {
                    clear(publicKey);
                    throw new IllegalArgumentException(
                        "recipient mlkem768Kid hint does not match the resolved key record"
                    );
                }
                if (!seenKids.add(derivedKid)) {
                    clear(publicKey);
                    throw new IllegalArgumentException("duplicate recipient X25519 kid");
                }
                publicKeys.add(publicKey);
            }
            return publicKeys;
        } catch (RuntimeException | Error failure) {
            clearAll(publicKeys);
            throw failure;
        }
    }

    private SenderEncryptionKeyLease openSenderEncryption(
        com.windletter.api.model.SenderEncryptionIdentityRef identity
    ) {
        Optional<SenderEncryptionKeyLease> opened = senderEncryptionKeys.open(identity);
        if (opened == null) {
            throw new IllegalStateException("sender encryption key store returned null");
        }
        return opened.orElseThrow(
            () -> new IllegalStateException("sender encryption identity was not found")
        );
    }

    private SigningIdentityLease openSigningIdentity(SigningIdentityRef identity) {
        Optional<SigningIdentityLease> opened = identities.openSigningIdentity(identity);
        if (opened == null) {
            throw new IllegalStateException("identity service returned null signing lease result");
        }
        return opened.orElseThrow(
            () -> new IllegalStateException("signing identity was not found")
        );
    }

    private static X25519PrivateKeyHandle validatedSenderEncryptionKey(
        SenderEncryptionKeyLease lease
    ) {
        X25519PrivateKeyHandle handle = lease.x25519PrivateKey();
        byte[] publicKey = handle.publicKey();
        try {
            if (!lease.kid().equals(X25519KeyId.derive(publicKey))) {
                throw new IllegalStateException(
                    "sender encryption lease kid does not match its public key"
                );
            }
            return handle;
        } finally {
            clear(publicKey);
        }
    }

    private static Ed25519PrivateKeyHandle validatedSigningKey(
        SigningIdentityRef requested,
        SigningIdentityLease lease
    ) {
        if (!requested.identityId().equals(lease.identityId())) {
            throw new IllegalStateException("signing lease identity does not match the request");
        }
        if (!isBlank(requested.signingKid())
            && !requested.signingKid().equals(lease.signingKid())) {
            throw new IllegalArgumentException("signingKid hint does not match the opened identity");
        }

        Ed25519PrivateKeyHandle handle = lease.ed25519PrivateKey();
        byte[] publicKey = handle.publicKey();
        try {
            if (!lease.signingKid().equals(Ed25519KeyId.derive(publicKey))) {
                throw new IllegalStateException("signing lease kid does not match its public key");
            }
            return handle;
        } finally {
            clear(publicKey);
        }
    }

    private static ProtocolPayload toProtocolPayload(Payload payload) {
        byte[] data = payload.data();
        try {
            return new ProtocolPayload(payload.contentType(), data, payload.originalSize());
        } finally {
            clear(data);
        }
    }

    private static EncryptedMessage rawMessage(String wireJson) {
        return new EncryptedMessage(wireJson, null, null, ArmorFormat.NONE);
    }

    private static void requireRawWire(ArmorFormat format, java.util.Map<String, Object> headers) {
        if (format != ArmorFormat.NONE) {
            throw new IllegalArgumentException("Phase 6 sender supports only ArmorFormat.NONE");
        }
        if (!headers.isEmpty()) {
            throw new IllegalArgumentException(
                "customHeaders are not defined by the Wind Letter v1.0 inner profile"
            );
        }
    }

    private static void requirePublicX25519(WindMode mode, KeyAlgProfile keyAlgProfile) {
        if (mode != WindMode.PUBLIC || keyAlgProfile != KeyAlgProfile.X25519) {
            throw new UnsupportedOperationException(
                "this implementation stage currently supports only public/X25519"
            );
        }
    }

    private static <T> T requireDependency(T value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    private static void requireRequest(Object request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static void clearAll(List<byte[]> values) {
        for (byte[] value : values) {
            clear(value);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
