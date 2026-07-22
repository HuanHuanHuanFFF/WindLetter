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
import com.windletter.api.spi.SigningIdentityLease;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.flow.ObfuscationX25519SignedSender;
import com.windletter.protocol.flow.ObfuscationX25519UnsignedSender;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.recipient.ObfuscationX25519RecipientBuilder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Obfuscation X25519 sender mapping; encryption always uses a fresh ephemeral key. */
final class ObfuscationX25519SenderOrchestrator {

    private final RecipientPublicKeyResolver recipientKeys;
    private final IdentityService identities;
    private final ObfuscationX25519UnsignedSender unsignedSender;
    private final ObfuscationX25519SignedSender signedSender;

    ObfuscationX25519SenderOrchestrator(
        RecipientPublicKeyResolver recipientKeys,
        IdentityService identities
    ) {
        this.recipientKeys = recipientKeys;
        this.identities = identities;
        ObfuscationX25519RecipientBuilder recipientBuilder =
            new ObfuscationX25519RecipientBuilder(
                new BouncyCastleX25519Crypto(),
                new BouncyCastleHkdfCrypto(),
                new BouncyCastleA256KeyWrapCrypto()
            );
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        this.unsignedSender = new ObfuscationX25519UnsignedSender(recipientBuilder, gcm);
        this.signedSender = new ObfuscationX25519SignedSender(
            recipientBuilder,
            gcm,
            new BouncyCastleEd25519Crypto()
        );
    }

    EncryptedMessage encrypt(EncryptRequest request) {
        List<byte[]> recipients = resolveRecipients(request.recipients());
        try {
            ObfuscationX25519UnsignedSender.Result result = unsignedSender.send(
                new ObfuscationX25519UnsignedSender.Request(
                    toProtocolPayload(request.payload()),
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    recipients
                )
            );
            return rawMessage(result.wireJson());
        } finally {
            clearAll(recipients);
        }
    }

    EncryptedMessage encryptAndSign(EncryptAndSignRequest request) {
        List<byte[]> recipients = resolveRecipients(request.recipients());
        try (SigningIdentityLease signingLease = openSigningIdentity(
            request.senderSigningIdentity()
        )) {
            ObfuscationX25519SignedSender.Result result = signedSender.send(
                new ObfuscationX25519SignedSender.Request(
                    toProtocolPayload(request.payload()),
                    UUID.randomUUID().toString(),
                    Instant.now().getEpochSecond(),
                    validatedSigningKey(request.senderSigningIdentity(), signingLease),
                    recipients
                )
            );
            return rawMessage(result.wireJson());
        } finally {
            clearAll(recipients);
        }
    }

    private List<byte[]> resolveRecipients(List<RecipientRef> requested) {
        if (requested.size() > 32) {
            throw new IllegalArgumentException("recipients must contain at most 32 entries");
        }
        List<byte[]> publicKeys = new ArrayList<>(requested.size());
        Set<String> seenKids = new HashSet<>(requested.size());
        try {
            for (RecipientRef recipient : requested) {
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
                boolean accepted = false;
                try {
                    String derivedKid = X25519KeyId.derive(publicKey);
                    if (!derivedKid.equals(material.x25519Kid())) {
                        throw new IllegalStateException(
                            "recipient X25519 key record does not match its public key"
                        );
                    }
                    if (!derivedKid.equals(recipient.x25519Kid())) {
                        throw new IllegalArgumentException(
                            "recipient x25519Kid does not match the resolved public key"
                        );
                    }
                    if (!isBlank(recipient.mlkem768Kid())
                        && !recipient.mlkem768Kid().equals(material.mlkem768Kid())) {
                        throw new IllegalArgumentException(
                            "recipient mlkem768Kid hint does not match the resolved key record"
                        );
                    }
                    if (!seenKids.add(derivedKid)) {
                        throw new IllegalArgumentException("duplicate recipient X25519 kid");
                    }
                    publicKeys.add(publicKey);
                    accepted = true;
                } finally {
                    if (!accepted) {
                        clear(publicKey);
                    }
                }
            }
            return publicKeys;
        } catch (RuntimeException | Error failure) {
            clearAll(publicKeys);
            throw failure;
        }
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

    private static void clearAll(List<byte[]> values) {
        if (values != null) {
            for (byte[] value : values) {
                clear(value);
            }
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
