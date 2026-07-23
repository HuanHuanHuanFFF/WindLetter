package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientBuilder;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientKeys;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/** Complete sender flow for the obfuscation/X25519ML-KEM-768/signed profile. */
public final class ObfuscationHybridSignedSender {

    private static final int CEK_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int ED25519_PUBLIC_KEY_LENGTH = 32;
    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int MAX_RECIPIENTS = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final ObfuscationHybridRecipientBuilder recipientBuilder;
    private final A256GcmCrypto gcm;
    private final Ed25519Crypto ed25519;
    private final SecureRandom secureRandom;
    private final OuterAad outerAad = new OuterAad();
    private final OuterBinding outerBinding = new OuterBinding();
    private final SignedInnerCodec innerCodec = new SignedInnerCodec();
    private final JacksonOuterWireWriter writer = new JacksonOuterWireWriter();

    public ObfuscationHybridSignedSender(
            ObfuscationHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    ) {
        this(recipientBuilder, gcm, ed25519, new SecureRandom());
    }

    ObfuscationHybridSignedSender(
            ObfuscationHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519,
            SecureRandom secureRandom
    ) {
        if (recipientBuilder == null) {
            throw new IllegalArgumentException("recipientBuilder must not be null");
        }
        if (gcm == null) {
            throw new IllegalArgumentException("gcm must not be null");
        }
        if (ed25519 == null) {
            throw new IllegalArgumentException("ed25519 must not be null");
        }
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.recipientBuilder = recipientBuilder;
        this.gcm = gcm;
        this.ed25519 = ed25519;
        this.secureRandom = secureRandom;
    }

    public Result send(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] cek = null;
        byte[] iv = null;
        byte[] signingPublicKey = null;
        byte[] signingInput = null;
        byte[] signature = null;
        byte[] innerBytes = null;
        byte[] gcmAad = null;
        try {
            cek = new byte[CEK_LENGTH];
            secureRandom.nextBytes(cek);
            iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            ObfuscationHybridRecipientBuilder.PreparedRecipients prepared =
                    recipientBuilder.build(request.recipients(), cek);
            List<RecipientEntry> recipients = List.copyOf(
                    new ArrayList<>(prepared.recipients())
            );
            ProtectedHeader protectedHeader = new ProtectedHeader(
                    "wind+jwe",
                    "wind+jws",
                    "1.0",
                    "obfuscation",
                    "A256GCM",
                    "X25519ML-KEM-768",
                    prepared.epk()
            );
            String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(protectedHeader)
            ));
            String aad = outerAad.compute(recipients);
            OuterBinding.Hashes binding = outerBinding.compute(
                    protectedHeader, recipients
            );

            signingPublicKey = request.senderSigningPrivateKey().publicKey();
            if (signingPublicKey == null
                    || signingPublicKey.length != ED25519_PUBLIC_KEY_LENGTH) {
                throw new IllegalStateException(
                        "Ed25519 handle returned a non-32-byte public key"
                );
            }
            String signingKid = Ed25519KeyId.derive(signingPublicKey);
            try (SignedInnerCodec.Prepared signed = innerCodec.prepare(
                    new SignedInnerCodec.Message(
                            request.messageId(),
                            request.timestamp(),
                            request.payload(),
                            binding,
                            signingKid
                    )
            )) {
                signingInput = signed.signingInput();
                signature = ed25519.sign(
                        request.senderSigningPrivateKey(), signingInput
                );
                if (signature == null
                        || signature.length != ED25519_SIGNATURE_LENGTH) {
                    throw new IllegalStateException(
                            "Ed25519 provider returned a non-64-byte signature"
                    );
                }
                innerBytes = innerCodec.assemble(signed, signature);
            }

            gcmAad = outerAad.gcmInput(protectedValue, aad);
            AeadCiphertext encrypted = gcm.encrypt(cek, iv, gcmAad, innerBytes);
            if (encrypted == null) {
                throw new IllegalStateException(
                        "A256GCM provider returned no ciphertext"
                );
            }
            byte[] ciphertext = encrypted.ciphertext();
            try {
                if (ciphertext.length != innerBytes.length) {
                    throw new IllegalStateException(
                            "A256GCM provider returned a ciphertext with an unexpected length"
                    );
                }
            } finally {
                clear(ciphertext);
            }

            WindLetter message = new WindLetter(
                    protectedHeader,
                    protectedValue,
                    aad,
                    recipients,
                    iv,
                    encrypted.ciphertext(),
                    encrypted.tag()
            );
            return new Result(message, writer.write(message));
        } finally {
            clear(cek);
            clear(iv);
            clear(signingPublicKey);
            clear(signingInput);
            clear(signature);
            clear(innerBytes);
            clear(gcmAad);
        }
    }

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) {
            return false;
        }
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4
                    && uuid.variant() == 2
                    && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean containsPair(
            List<ObfuscationHybridRecipientKeys> values,
            byte[] x25519PublicKey,
            byte[] mlkem768PublicKey
    ) {
        for (ObfuscationHybridRecipientKeys value : values) {
            byte[] candidateX25519 = value.x25519PublicKey();
            byte[] candidateMlkem768 = value.mlkem768PublicKey();
            try {
                if (MessageDigest.isEqual(candidateX25519, x25519PublicKey)
                        && MessageDigest.isEqual(candidateMlkem768, mlkem768PublicKey)) {
                    return true;
                }
            } finally {
                clear(candidateX25519);
                clear(candidateMlkem768);
            }
        }
        return false;
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            Ed25519PrivateKeyHandle senderSigningPrivateKey,
            List<ObfuscationHybridRecipientKeys> recipients
    ) {
        public Request {
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException(
                        "messageId must be a canonical lowercase UUID v4"
                );
            }
            if (timestamp < 0 || timestamp > MAX_SAFE_JSON_INTEGER) {
                throw new IllegalArgumentException(
                        "timestamp is outside the supported range"
                );
            }
            if (senderSigningPrivateKey == null) {
                throw new IllegalArgumentException(
                        "senderSigningPrivateKey must not be null"
                );
            }
            if (recipients == null) {
                throw new IllegalArgumentException("recipients must not be null");
            }
            if (recipients.isEmpty() || recipients.size() > MAX_RECIPIENTS) {
                throw new IllegalArgumentException(
                        "recipients must contain 1..32 entries"
                );
            }

            List<ObfuscationHybridRecipientKeys> snapshots =
                    new ArrayList<>(recipients.size());
            for (ObfuscationHybridRecipientKeys keys : recipients) {
                if (keys == null) {
                    throw new IllegalArgumentException(
                            "recipients must not contain null"
                    );
                }
                byte[] x25519PublicKey = keys.x25519PublicKey();
                byte[] mlkem768PublicKey = keys.mlkem768PublicKey();
                try {
                    if (containsPair(
                            snapshots, x25519PublicKey, mlkem768PublicKey
                    )) {
                        throw new IllegalArgumentException(
                                "duplicate hybrid recipient key pair"
                        );
                    }
                    snapshots.add(new ObfuscationHybridRecipientKeys(
                            x25519PublicKey, mlkem768PublicKey
                    ));
                } finally {
                    clear(x25519PublicKey);
                    clear(mlkem768PublicKey);
                }
            }
            recipients = List.copyOf(snapshots);
        }

        @Override
        public List<ObfuscationHybridRecipientKeys> recipients() {
            return List.copyOf(recipients);
        }
    }

    public record Result(WindLetter message, String wireJson) {
        public Result {
            if (message == null) {
                throw new IllegalArgumentException("message must not be null");
            }
            if (wireJson == null || wireJson.isBlank()) {
                throw new IllegalArgumentException("wireJson must not be blank");
            }
        }
    }
}
