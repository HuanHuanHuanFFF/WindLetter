package com.windletter.api.impl;

import com.windletter.api.enums.ArmorFormat;
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
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.flow.PublicHybridSignedSender;
import com.windletter.protocol.flow.PublicHybridUnsignedSender;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.recipient.PublicHybridRecipientBuilder;
import com.windletter.protocol.recipient.PublicHybridRecipientKeys;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Public X25519/ML-KEM-768 sender mapping kept local to the API facade. */
final class PublicHybridSenderOrchestrator {

    private final RecipientPublicKeyResolver recipientKeys;
    private final SenderEncryptionKeyStore senderEncryptionKeys;
    private final IdentityService identities;
    private final PublicHybridUnsignedSender unsignedSender;
    private final PublicHybridSignedSender signedSender;

    PublicHybridSenderOrchestrator(
        RecipientPublicKeyResolver recipientKeys,
        SenderEncryptionKeyStore senderEncryptionKeys,
        IdentityService identities
    ) {
        this.recipientKeys = recipientKeys;
        this.senderEncryptionKeys = senderEncryptionKeys;
        this.identities = identities;

        PublicHybridKekDeriver kekDeriver = new PublicHybridKekDeriver(
            new BouncyCastleX25519Crypto(),
            new BouncyCastleMLKem768Crypto(),
            new BouncyCastleHkdfCrypto()
        );
        PublicHybridRecipientBuilder recipientBuilder = new PublicHybridRecipientBuilder(
            kekDeriver,
            new BouncyCastleA256KeyWrapCrypto()
        );
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.unsignedSender = new PublicHybridUnsignedSender(recipientBuilder, gcm);
        this.signedSender = new PublicHybridSignedSender(
            recipientBuilder,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
    }

    EncryptedMessage encrypt(EncryptRequest request) {
        List<PublicHybridRecipientKeys> recipients = resolveRecipients(request.recipients());
        try (SenderEncryptionKeyLease senderLease = openSenderEncryption(
            request.senderEncryptionIdentity()
        )) {
            PublicHybridUnsignedSender.Result result = unsignedSender.send(
                new PublicHybridUnsignedSender.Request(
                    toProtocolPayload(request.payload()),
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    validatedSenderEncryptionKey(senderLease),
                    recipients
                )
            );
            return rawMessage(result.wireJson());
        }
    }

    EncryptedMessage encryptAndSign(EncryptAndSignRequest request) {
        List<PublicHybridRecipientKeys> recipients = resolveRecipients(request.recipients());
        try (
            SenderEncryptionKeyLease senderLease = openSenderEncryption(
                request.senderEncryptionIdentity()
            );
            SigningIdentityLease signingLease = openSigningIdentity(request.senderSigningIdentity())
        ) {
            PublicHybridSignedSender.Result result = signedSender.send(
                new PublicHybridSignedSender.Request(
                    toProtocolPayload(request.payload()),
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    validatedSenderEncryptionKey(senderLease),
                    validatedSigningKey(request.senderSigningIdentity(), signingLease),
                    recipients
                )
            );
            return rawMessage(result.wireJson());
        }
    }

    private List<PublicHybridRecipientKeys> resolveRecipients(List<RecipientRef> requested) {
        if (requested.size() > 32) {
            throw new IllegalArgumentException("recipients must contain at most 32 entries");
        }
        List<PublicHybridRecipientKeys> recipients = new ArrayList<>(requested.size());
        Set<RecipientPair> seenPairs = new HashSet<>(requested.size());
        for (RecipientRef recipient : requested) {
            if (isBlank(recipient.x25519Kid()) && isBlank(recipient.mlkem768Kid())) {
                throw new IllegalArgumentException(
                    "each Hybrid recipient must provide at least one kid hint"
                );
            }

            Optional<RecipientPublicKeyMaterial> resolved = recipientKeys.resolve(recipient);
            if (resolved == null) {
                throw new IllegalStateException("recipient key resolver returned null");
            }
            RecipientPublicKeyMaterial material = resolved.orElseThrow(
                () -> new IllegalStateException("recipient public key pair was not found")
            );
            byte[] x25519PublicKey = material.x25519PublicKey();
            byte[] mlkem768PublicKey = material.mlkem768PublicKey();
            try {
                if (mlkem768PublicKey == null || isBlank(material.mlkem768Kid())) {
                    throw new IllegalStateException(
                        "recipient key resolver returned an incomplete Hybrid pair"
                    );
                }
                String x25519Kid = X25519KeyId.derive(x25519PublicKey);
                String mlkem768Kid = MLKem768KeyId.derive(mlkem768PublicKey);
                if (!x25519Kid.equals(material.x25519Kid())
                    || !mlkem768Kid.equals(material.mlkem768Kid())) {
                    throw new IllegalStateException(
                        "recipient Hybrid key record does not match its public keys"
                    );
                }
                if ((!isBlank(recipient.x25519Kid())
                        && !x25519Kid.equals(recipient.x25519Kid()))
                    || (!isBlank(recipient.mlkem768Kid())
                        && !mlkem768Kid.equals(recipient.mlkem768Kid()))) {
                    throw new IllegalArgumentException(
                        "recipient Hybrid kid hints do not match the resolved key pair"
                    );
                }
                if (!seenPairs.add(new RecipientPair(x25519Kid, mlkem768Kid))) {
                    throw new IllegalArgumentException("duplicate Hybrid recipient key pair");
                }
                recipients.add(new PublicHybridRecipientKeys(
                    x25519PublicKey,
                    mlkem768PublicKey
                ));
            } finally {
                clear(x25519PublicKey);
                clear(mlkem768PublicKey);
            }
        }
        return List.copyOf(recipients);
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

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record RecipientPair(String x25519Kid, String mlkem768Kid) {
    }
}
