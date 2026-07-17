package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Complete sender flow for the public/X25519/signed profile.
 */
public final class PublicX25519SignedSender {

    private static final int CEK_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int PUBLIC_KEY_LENGTH = 32;
    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int MAX_RECIPIENTS = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final PublicX25519RecipientBuilder recipientBuilder;
    private final A256GcmCrypto gcm;
    private final Ed25519Crypto ed25519;
    private final SecureRandom secureRandom;
    private final OuterAad outerAad = new OuterAad();
    private final OuterBinding outerBinding = new OuterBinding();
    private final SignedInnerCodec innerCodec = new SignedInnerCodec();
    private final JacksonOuterWireWriter writer = new JacksonOuterWireWriter();

    public PublicX25519SignedSender(
            PublicX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    ) {
        this(recipientBuilder, gcm, ed25519, new SecureRandom());
    }

    PublicX25519SignedSender(
            PublicX25519RecipientBuilder recipientBuilder,
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

        byte[] senderEncryptionPublicKey = null;
        byte[] senderSigningPublicKey = null;
        List<byte[]> recipientPublicKeys = null;
        byte[] cek = null;
        byte[] iv = null;
        byte[] signingInput = null;
        byte[] signature = null;
        byte[] innerBytes = null;
        byte[] gcmAad = null;
        try {
            cek = new byte[CEK_LENGTH];
            secureRandom.nextBytes(cek);
            iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            senderEncryptionPublicKey = request.senderEncryptionPrivateKey().publicKey();
            requireProviderPublicKey(senderEncryptionPublicKey, "X25519");
            ProtectedHeader protectedHeader = new ProtectedHeader(
                    "wind+jwe",
                    "wind+jws",
                    "1.0",
                    "public",
                    "A256GCM",
                    "X25519",
                    new SenderKid(X25519KeyId.derive(senderEncryptionPublicKey))
            );
            String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(protectedHeader)
            ));

            recipientPublicKeys = request.recipientPublicKeys();
            List<RecipientEntry> recipients = List.copyOf(new ArrayList<>(recipientBuilder.build(
                    request.senderEncryptionPrivateKey(), recipientPublicKeys, cek
            )));
            clearAll(recipientPublicKeys);
            recipientPublicKeys = null;

            String aad = outerAad.compute(recipients);
            OuterBinding.Hashes binding = outerBinding.compute(protectedHeader, recipients);

            senderSigningPublicKey = request.senderSigningPrivateKey().publicKey();
            requireProviderPublicKey(senderSigningPublicKey, "Ed25519");
            String signingKid = Ed25519KeyId.derive(senderSigningPublicKey);
            try (SignedInnerCodec.Prepared prepared = innerCodec.prepare(new SignedInnerCodec.Message(
                    request.messageId(),
                    request.timestamp(),
                    request.payload(),
                    binding,
                    signingKid
            ))) {
                signingInput = prepared.signingInput();
                signature = ed25519.sign(request.senderSigningPrivateKey(), signingInput);
                if (signature == null || signature.length != ED25519_SIGNATURE_LENGTH) {
                    throw new IllegalStateException("Ed25519 provider returned a non-64-byte signature");
                }
                innerBytes = innerCodec.assemble(prepared, signature);
            }

            gcmAad = outerAad.gcmInput(protectedValue, aad);
            AeadCiphertext encrypted = gcm.encrypt(cek, iv, gcmAad, innerBytes);
            if (encrypted == null) {
                throw new IllegalStateException("A256GCM provider returned no ciphertext");
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
            clear(senderEncryptionPublicKey);
            clear(senderSigningPublicKey);
            clearAll(recipientPublicKeys);
            clear(cek);
            clear(iv);
            clear(signingInput);
            clear(signature);
            clear(innerBytes);
            clear(gcmAad);
        }
    }

    private static void requireProviderPublicKey(byte[] publicKey, String algorithm) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalStateException(algorithm + " handle returned a non-32-byte public key");
        }
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

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) {
            return false;
        }
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4 && uuid.variant() == 2 && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            X25519PrivateKeyHandle senderEncryptionPrivateKey,
            Ed25519PrivateKeyHandle senderSigningPrivateKey,
            List<byte[]> recipientPublicKeys
    ) {
        public Request {
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException("messageId must be a canonical lowercase UUID v4");
            }
            if (timestamp < 0 || timestamp > MAX_SAFE_JSON_INTEGER) {
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (senderEncryptionPrivateKey == null) {
                throw new IllegalArgumentException("senderEncryptionPrivateKey must not be null");
            }
            if (senderSigningPrivateKey == null) {
                throw new IllegalArgumentException("senderSigningPrivateKey must not be null");
            }
            if (recipientPublicKeys == null) {
                throw new IllegalArgumentException("recipientPublicKeys must not be null");
            }
            if (recipientPublicKeys.isEmpty() || recipientPublicKeys.size() > MAX_RECIPIENTS) {
                throw new IllegalArgumentException("recipientPublicKeys must contain 1..32 entries");
            }

            List<byte[]> snapshots = new ArrayList<>(recipientPublicKeys.size());
            Set<String> seenKids = new HashSet<>(recipientPublicKeys.size());
            for (byte[] publicKey : recipientPublicKeys) {
                if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
                    throw new IllegalArgumentException(
                            "each recipient public key must contain exactly 32 bytes"
                    );
                }
                byte[] snapshot = publicKey.clone();
                if (!seenKids.add(X25519KeyId.derive(snapshot))) {
                    throw new IllegalArgumentException("duplicate recipient X25519 kid");
                }
                snapshots.add(snapshot);
            }
            recipientPublicKeys = List.copyOf(snapshots);
        }

        @Override
        public List<byte[]> recipientPublicKeys() {
            List<byte[]> copies = new ArrayList<>(recipientPublicKeys.size());
            for (byte[] publicKey : recipientPublicKeys) {
                copies.add(publicKey.clone());
            }
            return List.copyOf(copies);
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
