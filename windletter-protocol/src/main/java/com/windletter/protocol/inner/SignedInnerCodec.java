package com.windletter.protocol.inner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.ProtocolLimits;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.StrictJson;
import com.windletter.protocol.model.ProtocolPayload;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Strict codec for the flattened, Ed25519-signed WindLetter inner object.
 */
public final class SignedInnerCodec {

    private static final ObjectMapper STRICT_JSON = StrictJson.newMapper();
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final int SHA_256_BYTES = 32;
    private static final int ED25519_SIGNATURE_BYTES = 64;
    private static final String INNER_TYPE = "wind+jws";
    private static final String SIGNATURE_ALGORITHM = "EdDSA";
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private static final Set<String> ROOT_FIELDS = Set.of("protected", "payload", "signature");
    private static final Set<String> PROTECTED_FIELDS = Set.of(
            "typ", "alg", "kid", "ts", "wind_id", "jwe_protected_hash", "jwe_recipients_hash"
    );
    private static final Set<String> PAYLOAD_FIELDS = Set.of("meta", "body");
    private static final Set<String> META_FIELDS = Set.of("content_type", "original_size");
    private static final Set<String> BODY_FIELDS = Set.of("data");

    /**
     * Canonicalizes the protected header and payload and exposes their exact signing input.
     */
    public Prepared prepare(Message message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }

        ObjectNode protectedNode = JsonNodeFactory.instance.objectNode();
        protectedNode.put("typ", INNER_TYPE);
        protectedNode.put("alg", SIGNATURE_ALGORITHM);
        protectedNode.put("kid", message.signingKid());
        protectedNode.put("ts", message.timestamp());
        protectedNode.put("wind_id", message.messageId());
        protectedNode.put("jwe_protected_hash", Base64Url.encode(message.binding().protectedHash()));
        protectedNode.put("jwe_recipients_hash", Base64Url.encode(message.binding().recipientsHash()));

        ObjectNode payloadNode = payloadNode(message.payload());
        String protectedValue = Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode));
        String payloadValue = Base64Url.encode(JcsCanonicalizer.canonicalize(payloadNode));
        byte[] signingInput = signingInput(protectedValue, payloadValue);
        try {
            return new Prepared(protectedValue, payloadValue, signingInput);
        } finally {
            Arrays.fill(signingInput, (byte) 0);
        }
    }

    /**
     * Adds an Ed25519 signature to prepared segments and emits a canonical flattened JWS object.
     */
    public byte[] assemble(Prepared prepared, byte[] signature) {
        if (prepared == null) {
            throw new IllegalArgumentException("prepared must not be null");
        }
        if (signature == null || signature.length != ED25519_SIGNATURE_BYTES) {
            throw new IllegalArgumentException("signature must contain exactly 64 bytes");
        }

        ObjectNode root = JsonNodeFactory.instance.objectNode();
        root.put("protected", prepared.protectedValue());
        root.put("payload", prepared.payloadValue());
        root.put("signature", Base64Url.encode(signature));
        byte[] encoded = JcsCanonicalizer.canonicalize(root);
        if (encoded.length > ProtocolLimits.MAX_INNER_BYTES) {
            throw new IllegalArgumentException("encoded signed inner message exceeds the supported size");
        }
        return encoded;
    }

    /**
     * Strictly decodes a flattened JWS while retaining the exact received signing segments.
     */
    public Decoded decode(byte[] innerBytes) {
        if (innerBytes == null) {
            throw malformed("signed inner bytes must not be null");
        }
        if (innerBytes.length > ProtocolLimits.MAX_INNER_BYTES) {
            throw invalid("signed inner message exceeds the supported size");
        }

        ObjectNode root = requireObject(parseJson(innerBytes, "signed inner"), "signed inner");
        requireExactFields(root, ROOT_FIELDS, "signed inner");

        String protectedValue = requireText(root.get("protected"), "signed inner.protected");
        String payloadValue = requireText(root.get("payload"), "signed inner.payload");
        String signatureValue = requireText(root.get("signature"), "signed inner.signature");

        byte[] protectedBytes = null;
        byte[] payloadBytes = null;
        byte[] signature = null;
        byte[] exactSigningInput = null;
        byte[] protectedHash = null;
        byte[] recipientsHash = null;
        byte[] data = null;
        try {
            protectedBytes = decodeWireBase64Url(protectedValue, "signed inner.protected");
            payloadBytes = decodeWireBase64Url(payloadValue, "signed inner.payload");
            signature = decodeWireBase64Url(signatureValue, "signed inner.signature");
            exactSigningInput = signingInput(protectedValue, payloadValue);
            if (signature.length != ED25519_SIGNATURE_BYTES) {
                throw invalid("signed inner.signature must decode to exactly 64 bytes");
            }

            ObjectNode protectedNode = requireObject(
                    parseJson(protectedBytes, "signed inner protected header"),
                    "signed inner protected header"
            );
            requireExactFields(protectedNode, PROTECTED_FIELDS, "signed inner protected header");

            String typ = requireText(protectedNode.get("typ"), "signed inner protected header.typ");
            if (!INNER_TYPE.equals(typ)) {
                throw invalid("signed inner protected header.typ must be wind+jws");
            }
            String algorithm = requireText(protectedNode.get("alg"), "signed inner protected header.alg");
            if (!SIGNATURE_ALGORITHM.equals(algorithm)) {
                throw invalid("signed inner protected header.alg must be EdDSA");
            }
            String signingKid = requireText(protectedNode.get("kid"), "signed inner protected header.kid");
            byte[] signingKidBytes = decodeFixedLength(
                    signingKid, "signed inner protected header.kid", SHA_256_BYTES
            );
            Arrays.fill(signingKidBytes, (byte) 0);

            long timestamp = requireIntegralLong(protectedNode.get("ts"), "signed inner protected header.ts");
            if (!validTimestamp(timestamp)) {
                throw invalid("signed inner protected header.ts is outside the supported range");
            }
            String messageId = requireText(
                    protectedNode.get("wind_id"), "signed inner protected header.wind_id"
            );
            if (!validMessageId(messageId)) {
                throw invalid("signed inner protected header.wind_id must be a canonical lowercase UUID v4");
            }

            protectedHash = decodeFixedLength(
                    requireText(protectedNode.get("jwe_protected_hash"),
                            "signed inner protected header.jwe_protected_hash"),
                    "signed inner protected header.jwe_protected_hash",
                    SHA_256_BYTES
            );
            recipientsHash = decodeFixedLength(
                    requireText(protectedNode.get("jwe_recipients_hash"),
                            "signed inner protected header.jwe_recipients_hash"),
                    "signed inner protected header.jwe_recipients_hash",
                    SHA_256_BYTES
            );

            ObjectNode parsedPayload = requireObject(
                    parseJson(payloadBytes, "signed inner payload"), "signed inner payload"
            );
            requireExactFields(parsedPayload, PAYLOAD_FIELDS, "signed inner payload");
            ObjectNode meta = requireObject(parsedPayload.get("meta"), "signed inner payload.meta");
            requireExactFields(meta, META_FIELDS, "signed inner payload.meta");
            ObjectNode body = requireObject(parsedPayload.get("body"), "signed inner payload.body");
            requireExactFields(body, BODY_FIELDS, "signed inner payload.body");

            String contentType = requireText(meta.get("content_type"), "signed inner payload.meta.content_type");
            if (contentType.isBlank()) {
                throw invalid("signed inner payload.meta.content_type must be non-blank");
            }
            long originalSize = requireIntegralLong(
                    meta.get("original_size"), "signed inner payload.meta.original_size"
            );
            if (originalSize < 0 || originalSize > ProtocolLimits.MAX_PAYLOAD_BYTES) {
                throw invalid("signed inner payload.meta.original_size is outside the supported range");
            }
            String dataValue = requireText(body.get("data"), "signed inner payload.body.data");
            data = decodeWireBase64UrlAllowEmpty(dataValue, "signed inner payload.body.data");
            if (data.length > ProtocolLimits.MAX_PAYLOAD_BYTES) {
                throw invalid("signed inner payload.body.data exceeds the supported size");
            }
            if (originalSize != data.length) {
                throw invalid("signed inner payload.meta.original_size does not match decoded data");
            }

            Message message = new Message(
                    messageId,
                    timestamp,
                    new ProtocolPayload(contentType, data, originalSize),
                    new OuterBinding.Hashes(protectedHash, recipientsHash),
                    signingKid
            );
            return new Decoded(message, exactSigningInput, signature);
        } finally {
            if (protectedBytes != null) {
                Arrays.fill(protectedBytes, (byte) 0);
            }
            if (payloadBytes != null) {
                Arrays.fill(payloadBytes, (byte) 0);
            }
            if (protectedHash != null) {
                Arrays.fill(protectedHash, (byte) 0);
            }
            if (recipientsHash != null) {
                Arrays.fill(recipientsHash, (byte) 0);
            }
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
            if (signature != null) {
                Arrays.fill(signature, (byte) 0);
            }
            if (exactSigningInput != null) {
                Arrays.fill(exactSigningInput, (byte) 0);
            }
        }
    }

    private static ObjectNode payloadNode(ProtocolPayload payload) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("content_type", payload.contentType());
        meta.put("original_size", payload.originalSize());

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        byte[] data = payload.data();
        try {
            body.put("data", Base64Url.encode(data));
        } finally {
            Arrays.fill(data, (byte) 0);
        }

        ObjectNode payloadNode = JsonNodeFactory.instance.objectNode();
        payloadNode.set("meta", meta);
        payloadNode.set("body", body);
        return payloadNode;
    }

    private static JsonNode parseJson(byte[] bytes, String fieldPath) {
        String json;
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            json = decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw malformed(fieldPath + " is not strict UTF-8 JSON", e);
        }

        try {
            return STRICT_JSON.readTree(json);
        } catch (IOException | RuntimeException e) {
            if (e instanceof ProtocolException protocolException) {
                throw protocolException;
            }
            throw malformed(fieldPath + " is not strict UTF-8 JSON", e);
        }
    }

    private static byte[] decodeFixedLength(String value, String fieldPath, int expectedLength) {
        byte[] decoded = decodeWireBase64Url(value, fieldPath);
        if (decoded.length != expectedLength) {
            Arrays.fill(decoded, (byte) 0);
            throw invalid(fieldPath + " must decode to exactly " + expectedLength + " bytes");
        }
        return decoded;
    }

    private static byte[] decodeWireBase64Url(String value, String fieldPath) {
        try {
            return Base64Url.decodeCanonical(value, fieldPath);
        } catch (ProtocolException e) {
            throw invalid(fieldPath + " must use canonical unpadded Base64URL");
        }
    }

    private static byte[] decodeWireBase64UrlAllowEmpty(String value, String fieldPath) {
        if (value != null && value.isEmpty()) {
            return new byte[0];
        }
        return decodeWireBase64Url(value, fieldPath);
    }

    private static ObjectNode requireObject(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isObject()) {
            throw malformed(fieldPath + " must be a non-null object");
        }
        return (ObjectNode) node;
    }

    private static String requireText(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isTextual()) {
            throw malformed(fieldPath + " must be a non-null string");
        }
        return node.textValue();
    }

    private static long requireIntegralLong(JsonNode node, String fieldPath) {
        if (node == null || node.isNull() || !node.isNumber()) {
            throw malformed(fieldPath + " must be a non-null number");
        }
        if (!node.isIntegralNumber() || !node.canConvertToLong()) {
            throw invalid(fieldPath + " must be represented as an integral JSON number");
        }
        return node.longValue();
    }

    private static void requireExactFields(ObjectNode node, Set<String> expected, String fieldPath) {
        node.fieldNames().forEachRemaining(name -> {
            if (!expected.contains(name)) {
                throw invalid(fieldPath + " contains unknown or disallowed field: " + name);
            }
        });
        for (String name : expected) {
            if (!node.has(name)) {
                throw invalid(fieldPath + " is missing required field: " + name);
            }
        }
    }

    private static byte[] signingInput(String protectedValue, String payloadValue) {
        return (protectedValue + "." + payloadValue).getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean validTimestamp(long timestamp) {
        return timestamp >= 0 && timestamp <= MAX_SAFE_JSON_INTEGER;
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

    private static void validateSigningKid(String signingKid) {
        byte[] decoded = null;
        try {
            decoded = Base64Url.decodeCanonical(signingKid, "signingKid");
            if (decoded.length != SHA_256_BYTES) {
                throw new IllegalArgumentException("signingKid must decode to exactly 32 bytes");
            }
        } catch (ProtocolException e) {
            throw new IllegalArgumentException("signingKid must be canonical Base64URL", e);
        } finally {
            if (decoded != null) {
                Arrays.fill(decoded, (byte) 0);
            }
        }
    }

    private static ProtocolException malformed(String message) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message);
    }

    private static ProtocolException malformed(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message, cause);
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    /**
     * Semantic values used to construct or recovered from a signed inner message.
     */
    public record Message(
            String messageId,
            long timestamp,
            ProtocolPayload payload,
            OuterBinding.Hashes binding,
            String signingKid
    ) {
        public Message {
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException("messageId must be a canonical lowercase UUID v4");
            }
            if (!validTimestamp(timestamp)) {
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (binding == null) {
                throw new IllegalArgumentException("binding must not be null");
            }
            validateSigningKid(signingKid);
        }
    }

    /**
     * Canonical encoded segments and their exact mutable signing-input bytes.
     */
    public static final class Prepared implements AutoCloseable {

        private final String protectedValue;
        private final String payloadValue;
        private final byte[] signingInput;

        private Prepared(String protectedValue, String payloadValue, byte[] signingInput) {
            this.protectedValue = protectedValue;
            this.payloadValue = payloadValue;
            this.signingInput = Arrays.copyOf(signingInput, signingInput.length);
        }

        public String protectedValue() {
            return protectedValue;
        }

        public String payloadValue() {
            return payloadValue;
        }

        public byte[] signingInput() {
            return Arrays.copyOf(signingInput, signingInput.length);
        }

        @Override
        public void close() {
            Arrays.fill(signingInput, (byte) 0);
        }
    }

    /**
     * Strictly decoded message plus exact mutable verification input and signature bytes.
     */
    public static final class Decoded implements AutoCloseable {

        private final Message message;
        private final byte[] signingInput;
        private final byte[] signature;

        private Decoded(Message message, byte[] signingInput, byte[] signature) {
            this.message = message;
            this.signingInput = Arrays.copyOf(signingInput, signingInput.length);
            this.signature = Arrays.copyOf(signature, signature.length);
        }

        public Message message() {
            return message;
        }

        public byte[] signingInput() {
            return Arrays.copyOf(signingInput, signingInput.length);
        }

        public byte[] signature() {
            return Arrays.copyOf(signature, signature.length);
        }

        @Override
        public void close() {
            Arrays.fill(signingInput, (byte) 0);
            Arrays.fill(signature, (byte) 0);
        }
    }
}
