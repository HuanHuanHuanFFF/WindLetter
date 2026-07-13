package com.windletter.protocol.flow;

import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.inner.UnsignedInnerCodec;
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
 * Complete sender flow for the stage-one public/X25519/unsigned profile.
 */
public final class PublicX25519UnsignedSender {

    private static final int CEK_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int MAX_RECIPIENTS = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final PublicX25519RecipientBuilder recipientBuilder;
    private final A256GcmCrypto gcm;
    private final SecureRandom secureRandom;
    private final OuterAad outerAad = new OuterAad();
    private final OuterBinding outerBinding = new OuterBinding();
    private final UnsignedInnerCodec innerCodec = new UnsignedInnerCodec();
    private final JacksonOuterWireWriter writer = new JacksonOuterWireWriter();

    public PublicX25519UnsignedSender(
            PublicX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm
    ) {
        this(recipientBuilder, gcm, new SecureRandom());
    }

    PublicX25519UnsignedSender(
            PublicX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            SecureRandom secureRandom
    ) {
        if (recipientBuilder == null) {
            throw new IllegalArgumentException("recipientBuilder must not be null");
        }
        if (gcm == null) {
            throw new IllegalArgumentException("gcm must not be null");
        }
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.recipientBuilder = recipientBuilder;
        this.gcm = gcm;
        this.secureRandom = secureRandom;
    }

    public Result send(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] senderPublicKey = null;
        byte[] cek = null;
        byte[] iv = null;
        byte[] innerBytes = null;
        byte[] gcmAad = null;
        try {
            cek = new byte[CEK_LENGTH];
            secureRandom.nextBytes(cek);
            iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            senderPublicKey = request.senderPrivateKey().publicKey();
            if (senderPublicKey == null || senderPublicKey.length != X25519_PUBLIC_KEY_LENGTH) {
                throw new IllegalStateException("X25519 handle returned a non-32-byte public key");
            }
            ProtectedHeader protectedHeader = new ProtectedHeader(
                    "wind+jwe",
                    "wind+inner",
                    "1.0",
                    "public",
                    "A256GCM",
                    "X25519",
                    new SenderKid(X25519KeyId.derive(senderPublicKey))
            );
            String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(
                    OuterJsonMapper.toProtectedJson(protectedHeader)
            ));

            List<RecipientEntry> recipients = List.copyOf(new ArrayList<>(recipientBuilder.build(
                    request.senderPrivateKey(), request.recipientPublicKeys(), cek
            )));
            String aad = outerAad.compute(recipients);
            OuterBinding.Hashes binding = outerBinding.compute(protectedHeader, recipients);
            innerBytes = innerCodec.encode(new UnsignedInnerCodec.Message(
                    request.messageId(),
                    request.timestamp(),
                    request.payload(),
                    binding
            ));
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
            clear(senderPublicKey);
            clear(cek);
            clear(iv);
            clear(innerBytes);
            clear(gcmAad);
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
            X25519PrivateKeyHandle senderPrivateKey,
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
            if (senderPrivateKey == null) {
                throw new IllegalArgumentException("senderPrivateKey must not be null");
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
                if (publicKey == null || publicKey.length != X25519_PUBLIC_KEY_LENGTH) {
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
