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
import com.windletter.protocol.recipient.ObfuscationX25519RecipientBuilder;
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

/** Complete sender flow for the obfuscation/X25519/signed profile. */
public final class ObfuscationX25519SignedSender {

    private static final int CEK_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int PUBLIC_KEY_LENGTH = 32;
    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int MAX_RECIPIENTS = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final ObfuscationX25519RecipientBuilder recipientBuilder;
    private final A256GcmCrypto gcm;
    private final Ed25519Crypto ed25519;
    private final SecureRandom secureRandom;
    private final OuterAad outerAad = new OuterAad();
    private final OuterBinding outerBinding = new OuterBinding();
    private final SignedInnerCodec innerCodec = new SignedInnerCodec();
    private final JacksonOuterWireWriter writer = new JacksonOuterWireWriter();

    public ObfuscationX25519SignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    ) {
        this(recipientBuilder, gcm, ed25519, new SecureRandom());
    }

    ObfuscationX25519SignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
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

        List<byte[]> recipientPublicKeys = null;
        byte[] cek = null;
        byte[] iv = null;
        byte[] signingPublicKey = null;
        byte[] signingInput = null;
        byte[] signature = null;
        byte[] innerBytes = null;
        byte[] gcmAad = null;
        try {
            recipientPublicKeys = request.recipientPublicKeys();
            cek = new byte[CEK_LENGTH];
            secureRandom.nextBytes(cek);
            iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            ObfuscationX25519RecipientBuilder.PreparedRecipients preparedRecipients =
                    recipientBuilder.build(recipientPublicKeys, cek);
            List<RecipientEntry> recipients = List.copyOf(
                    new ArrayList<>(preparedRecipients.recipients())
            );
            ProtectedHeader protectedHeader = new ProtectedHeader(
                    "wind+jwe",
                    "wind+jws",
                    "1.0",
                    "obfuscation",
                    "A256GCM",
                    "X25519",
                    preparedRecipients.epk()
            );
            String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(protectedHeader)
            ));
            String aad = outerAad.compute(recipients);
            OuterBinding.Hashes binding = outerBinding.compute(protectedHeader, recipients);

            signingPublicKey = request.senderSigningPrivateKey().publicKey();
            requireProviderPublicKey(signingPublicKey);
            String signingKid = Ed25519KeyId.derive(signingPublicKey);
            try (SignedInnerCodec.Prepared prepared = innerCodec.prepare(
                    new SignedInnerCodec.Message(
                            request.messageId(), request.timestamp(), request.payload(),
                            binding, signingKid
                    ))) {
                signingInput = prepared.signingInput();
                signature = ed25519.sign(request.senderSigningPrivateKey(), signingInput);
                if (signature == null || signature.length != ED25519_SIGNATURE_LENGTH) {
                    throw new IllegalStateException(
                            "Ed25519 provider returned a non-64-byte signature"
                    );
                }
                innerBytes = innerCodec.assemble(prepared, signature);
            }

            gcmAad = outerAad.gcmInput(protectedValue, aad);
            AeadCiphertext encrypted = gcm.encrypt(cek, iv, gcmAad, innerBytes);
            if (encrypted == null) {
                throw new IllegalStateException("A256GCM provider returned no ciphertext");
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
            clearAll(recipientPublicKeys);
            clear(cek);
            clear(iv);
            clear(signingPublicKey);
            clear(signingInput);
            clear(signature);
            clear(innerBytes);
            clear(gcmAad);
        }
    }

    private static void requireProviderPublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalStateException(
                    "Ed25519 handle returned a non-32-byte public key"
            );
        }
    }

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) {
            return false;
        }
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4 && uuid.variant() == 2
                    && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void clearAll(List<byte[]> values) {
        if (values != null) {
            for (byte[] value : values) clear(value);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            Ed25519PrivateKeyHandle senderSigningPrivateKey,
            List<byte[]> recipientPublicKeys
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
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (senderSigningPrivateKey == null) {
                throw new IllegalArgumentException(
                        "senderSigningPrivateKey must not be null"
                );
            }
            if (recipientPublicKeys == null) {
                throw new IllegalArgumentException("recipientPublicKeys must not be null");
            }
            if (recipientPublicKeys.isEmpty() || recipientPublicKeys.size() > MAX_RECIPIENTS) {
                throw new IllegalArgumentException(
                        "recipientPublicKeys must contain 1..32 entries"
                );
            }

            List<byte[]> snapshots = new ArrayList<>(recipientPublicKeys.size());
            try {
                for (byte[] publicKey : recipientPublicKeys) {
                    if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
                        throw new IllegalArgumentException(
                                "each recipient public key must contain exactly 32 bytes"
                        );
                    }
                    byte[] snapshot = publicKey.clone();
                    if (contains(snapshots, snapshot)) {
                        clear(snapshot);
                        throw new IllegalArgumentException(
                                "duplicate recipient X25519 public key"
                        );
                    }
                    snapshots.add(snapshot);
                }
                recipientPublicKeys = List.copyOf(snapshots);
            } catch (RuntimeException failure) {
                clearAll(snapshots);
                throw failure;
            }
        }

        @Override
        public List<byte[]> recipientPublicKeys() {
            List<byte[]> copies = new ArrayList<>(recipientPublicKeys.size());
            for (byte[] publicKey : recipientPublicKeys) copies.add(publicKey.clone());
            return List.copyOf(copies);
        }

        private static boolean contains(List<byte[]> values, byte[] candidate) {
            for (byte[] value : values) {
                if (MessageDigest.isEqual(value, candidate)) return true;
            }
            return false;
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
