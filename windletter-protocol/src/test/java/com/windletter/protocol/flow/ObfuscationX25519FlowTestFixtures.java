package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.ObfuscationX25519KeyDeriver;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.ObfuscationX25519RecipientBuilder;
import com.windletter.protocol.routing.ObfuscationX25519CekRecovery;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class ObfuscationX25519FlowTestFixtures {

    static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    static final String IDENTITY_ID = "trusted-sender-1";
    static final long TIMESTAMP = 1_731_800_000L;
    static final byte[] BINARY = {0, 1, 0x7f, (byte) 0x80, (byte) 0xff};
    private static final ObjectMapper JSON = new ObjectMapper();

    private ObfuscationX25519FlowTestFixtures() {
    }

    static ObjectNode object(String json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    static String json(ObjectNode node) {
        try {
            return JSON.writeValueAsString(node);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    static void recomputeAad(ObjectNode root) {
        root.put("aad", Base64Url.encode(JcsCanonicalizer.canonicalize(root.get("recipients"))));
    }

    static String protectedField(String wire, String name, String value) {
        ObjectNode root = object(wire);
        byte[] bytes = Base64Url.decodeCanonical(root.get("protected").textValue(), "test.protected");
        try {
            ObjectNode header = object(new String(bytes, StandardCharsets.UTF_8));
            header.put(name, value);
            root.put("protected", Base64Url.encode(JcsCanonicalizer.canonicalize(header)));
            return json(root);
        } finally {
            clear(bytes);
        }
    }

    static void assertCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
    }

    static boolean allZero(byte[] value) {
        if (value == null) return false;
        int aggregate = 0;
        for (byte b : value) aggregate |= b;
        return aggregate == 0;
    }

    static byte[] filled(int size, int value) {
        byte[] result = new byte[size];
        Arrays.fill(result, (byte) value);
        return result;
    }

    static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    static final class Fixture implements AutoCloseable {
        final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        final BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
        final X25519PrivateKeyHandle first = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle second = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle third = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle unrelated = x25519.generatePrivateKey();
        final Ed25519PrivateKeyHandle senderSigning = ed25519.generatePrivateKey();
        final Ed25519PrivateKeyHandle unrelatedSigning = ed25519.generatePrivateKey();
        final String signingKid = deriveSigningKid(senderSigning);

        ProtocolPayload binaryPayload() {
            return new ProtocolPayload("application/octet-stream", BINARY, BINARY.length);
        }

        ProtocolPayload textPayload() {
            byte[] bytes = "WindLetter 文本".getBytes(StandardCharsets.UTF_8);
            return new ProtocolPayload("text/plain; charset=utf-8", bytes, bytes.length);
        }

        ProtocolPayload emptyPayload() {
            return new ProtocolPayload("application/octet-stream", new byte[0], 0);
        }

        ObfuscationX25519RecipientBuilder builder() {
            return new ObfuscationX25519RecipientBuilder(x25519, hkdf, keyWrap);
        }

        ObfuscationX25519CekRecovery recovery() {
            return new ObfuscationX25519CekRecovery(
                    new ObfuscationX25519KeyDeriver(x25519, hkdf), keyWrap
            );
        }

        ObfuscationX25519UnsignedSender sender() {
            return new ObfuscationX25519UnsignedSender(builder(), gcm);
        }

        ObfuscationX25519UnsignedReceiver receiver() {
            return new ObfuscationX25519UnsignedReceiver(recovery(), gcm);
        }

        ObfuscationX25519SignedSender signedSender() {
            return new ObfuscationX25519SignedSender(builder(), gcm, ed25519);
        }

        ObfuscationX25519SignedReceiver signedReceiver() {
            return new ObfuscationX25519SignedReceiver(recovery(), gcm, ed25519);
        }

        TrustedEd25519Key trustedSigningKey() {
            return new TrustedEd25519Key(IDENTITY_ID, signingKid, senderSigning.publicKey());
        }

        String send(ProtocolPayload payload) {
            return sender().send(new ObfuscationX25519UnsignedSender.Request(
                    payload, MESSAGE_ID, TIMESTAMP,
                    List.of(first.publicKey(), second.publicKey(), third.publicKey())
            )).wireJson();
        }

        String sendSigned(ProtocolPayload payload) {
            return signedSender().send(new ObfuscationX25519SignedSender.Request(
                    payload, MESSAGE_ID, TIMESTAMP, senderSigning,
                    List.of(first.publicKey(), second.publicKey(), third.publicKey())
            )).wireJson();
        }

        ObfuscationX25519UnsignedReceiver.Request request(
                String wire,
                List<X25519PrivateKeyHandle> handles
        ) {
            return new ObfuscationX25519UnsignedReceiver.Request(wire, handles);
        }

        ObfuscationX25519SignedReceiver.Request signedRequest(
                String wire,
                Ed25519VerificationKeyResolver resolver,
                List<X25519PrivateKeyHandle> handles
        ) {
            return new ObfuscationX25519SignedReceiver.Request(wire, resolver, handles);
        }

        String authenticatedWire(String originalWire, byte[] innerBytes) {
            WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
            byte[] cek = recovery().recover(
                    (com.windletter.protocol.wire.Epk) parsed.protectedHeader().senderInfo(),
                    parsed.recipients(), List.of(second)
            );
            byte[] aad = new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad());
            byte[] iv = parsed.iv();
            try {
                AeadCiphertext encrypted = gcm.encrypt(cek, iv, aad, innerBytes);
                return new JacksonOuterWireWriter().write(new WindLetter(
                        parsed.protectedHeader(), parsed.protectedValue(), parsed.aad(),
                        parsed.recipients(), iv, encrypted.ciphertext(), encrypted.tag()
                ));
            } finally {
                clear(cek);
                clear(aad);
                clear(iv);
            }
        }

        String bindingFailure(String originalWire) {
            byte[] inner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    MESSAGE_ID, TIMESTAMP, binaryPayload(),
                    new OuterBinding.Hashes(new byte[32], new byte[32])
            ));
            try {
                return authenticatedWire(originalWire, inner);
            } finally {
                clear(inner);
            }
        }

        String signedBindingFailure(String originalWire) {
            return authenticatedSignedWire(
                    originalWire,
                    new OuterBinding.Hashes(new byte[32], new byte[32]),
                    signingKid,
                    senderSigning
            );
        }

        String authenticatedSignedWire(
                String originalWire,
                OuterBinding.Hashes binding,
                String kid,
                Ed25519PrivateKeyHandle signingKey
        ) {
            byte[] signature = null;
            byte[] inner = null;
            try (SignedInnerCodec.Prepared prepared = new SignedInnerCodec().prepare(
                    new SignedInnerCodec.Message(
                            MESSAGE_ID, TIMESTAMP, binaryPayload(), binding, kid
                    ))) {
                byte[] signingInput = prepared.signingInput();
                try {
                    signature = ed25519.sign(signingKey, signingInput);
                } finally {
                    clear(signingInput);
                }
                inner = new SignedInnerCodec().assemble(prepared, signature);
                return authenticatedWire(originalWire, inner);
            } finally {
                clear(signature);
                clear(inner);
            }
        }

        String authenticatedNonCanonicalSignedWire(String originalWire) {
            WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
            OuterBinding.Hashes binding = new OuterBinding().compute(
                    parsed.protectedHeader(), parsed.recipients()
            );
            byte[] protectedHash = binding.protectedHash();
            byte[] recipientsHash = binding.recipientsHash();
            byte[] payloadData = binaryPayload().data();
            byte[] signingInput = null;
            byte[] signature = null;
            byte[] inner = null;
            try {
                String protectedJson = "{\"wind_id\":\"" + MESSAGE_ID
                        + "\", \"ts\":" + TIMESTAMP
                        + ", \"typ\":\"wind+jws\", \"kid\":\"" + signingKid
                        + "\", \"jwe_recipients_hash\":\"" + Base64Url.encode(recipientsHash)
                        + "\", \"jwe_protected_hash\":\"" + Base64Url.encode(protectedHash)
                        + "\", \"alg\":\"EdDSA\"}";
                String payloadJson = "{\"meta\":{\"original_size\":" + payloadData.length
                        + ",\"content_type\":\"application/octet-stream\"},"
                        + "\"body\":{\"data\":\"" + Base64Url.encode(payloadData) + "\"}}";
                String protectedValue = Base64Url.encode(
                        protectedJson.getBytes(StandardCharsets.UTF_8)
                );
                String payloadValue = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));
                signingInput = (protectedValue + "." + payloadValue)
                        .getBytes(StandardCharsets.US_ASCII);
                signature = ed25519.sign(senderSigning, signingInput);
                ObjectNode root = JSON.createObjectNode();
                root.put("signature", Base64Url.encode(signature));
                root.put("payload", payloadValue);
                root.put("protected", protectedValue);
                inner = JcsCanonicalizer.canonicalize(root);
                return authenticatedWire(originalWire, inner);
            } finally {
                clear(protectedHash);
                clear(recipientsHash);
                clear(payloadData);
                clear(signingInput);
                clear(signature);
                clear(inner);
            }
        }

        @Override
        public void close() {
            unrelatedSigning.close();
            senderSigning.close();
            unrelated.close();
            third.close();
            second.close();
            first.close();
        }

        private static String deriveSigningKid(Ed25519PrivateKeyHandle handle) {
            byte[] publicKey = handle.publicKey();
            try {
                return Ed25519KeyId.derive(publicKey);
            } finally {
                clear(publicKey);
            }
        }
    }

    static final class TrackingRandom extends SecureRandom {
        final java.util.ArrayList<byte[]> references = new java.util.ArrayList<>();
        private int calls;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, (byte) (0x51 + calls++));
            references.add(bytes);
        }
    }
}
