package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class ProtocolFlowTestFixtures {

    static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    static final long TIMESTAMP = 1_731_800_000L;
    static final String CONTENT_TYPE = "application/vnd.windletter.test+binary";
    static final byte[] BINARY_PAYLOAD = {0x00, 0x01, 0x7f, (byte) 0x80, (byte) 0xff, 0x42};

    private static final ObjectMapper JSON = new ObjectMapper();

    private ProtocolFlowTestFixtures() {
    }

    static RealFixture realFixture() {
        return new RealFixture();
    }

    static ObjectNode parseObject(String json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (Exception e) {
            throw new AssertionError("failed to parse test JSON", e);
        }
    }

    static String write(ObjectNode node) {
        try {
            return JSON.writeValueAsString(node);
        } catch (Exception e) {
            throw new AssertionError("failed to write test JSON", e);
        }
    }

    static void flipEncodedField(ObjectNode node, String field) {
        byte[] decoded = Base64Url.decodeCanonical(node.get(field).textValue(), "test." + field);
        try {
            decoded[0] ^= 1;
            node.put(field, Base64Url.encode(decoded));
        } finally {
            clear(decoded);
        }
    }

    static void recomputeAad(ObjectNode root) {
        root.put("aad", Base64Url.encode(JcsCanonicalizer.canonicalize(root.get("recipients"))));
    }

    static void reencodeProtectedWithWhitespace(ObjectNode root) {
        byte[] original = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        byte[] reencoded = null;
        try {
            String originalJson = new String(original, StandardCharsets.UTF_8);
            reencoded = (" \n" + originalJson).getBytes(StandardCharsets.UTF_8);
            JsonNode originalSemantics = JSON.readTree(original);
            JsonNode reencodedSemantics = JSON.readTree(reencoded);
            if (!originalSemantics.equals(reencodedSemantics)) {
                throw new AssertionError("protected test mutation changed JSON semantics");
            }
            root.put("protected", Base64Url.encode(reencoded));
        } catch (Exception e) {
            throw new AssertionError("failed to re-encode protected JSON", e);
        } finally {
            clear(original);
            clear(reencoded);
        }
    }

    static void assertProtocolCode(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
    }

    enum BindingTarget {
        PROTECTED,
        RECIPIENTS
    }

    static final class RealFixture implements AutoCloseable {

        final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        final PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(
                x25519, new BouncyCastleHkdfCrypto()
        );
        final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        final X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle firstRecipient = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle secondRecipient = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle thirdRecipient = x25519.generatePrivateKey();
        final X25519PrivateKeyHandle unrelatedRecipient = x25519.generatePrivateKey();

        ProtocolPayload binaryPayload() {
            return new ProtocolPayload(CONTENT_TYPE, BINARY_PAYLOAD, BINARY_PAYLOAD.length);
        }

        List<X25519PrivateKeyHandle> recipients() {
            return List.of(firstRecipient, secondRecipient, thirdRecipient);
        }

        String send(ProtocolPayload payload) {
            PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                    new PublicX25519RecipientBuilder(kekDeriver, keyWrap), gcm
            );
            return sendWith(sender, payload);
        }

        PublicX25519UnsignedReceiver receiver() {
            return new PublicX25519UnsignedReceiver(kekDeriver, keyWrap, gcm);
        }

        PublicX25519UnsignedReceiver.Request receiveRequest(
                String wireJson,
                X25519PrivateKeyHandle recipient
        ) {
            byte[] senderPublicKey = senderKey.publicKey();
            String senderKid = X25519KeyId.derive(senderPublicKey);
            clear(senderPublicKey);
            SenderX25519PublicKeyResolver resolver = requestedKid -> {
                if (!senderKid.equals(requestedKid)) {
                    return Optional.empty();
                }
                return Optional.of(senderKey.publicKey());
            };
            return new PublicX25519UnsignedReceiver.Request(
                    wireJson, resolver, List.of(recipient)
            );
        }

        String authenticatedBindingTamper(BindingTarget target) {
            byte[] knownCek = filled(32, 0x51);
            byte[] knownIv = filled(12, 0x61);
            byte[] protectedHash = null;
            byte[] recipientsHash = null;
            byte[] innerBytes = null;
            byte[] gcmAad = null;
            byte[] parsedIv = null;
            try {
                String originalWire = sendWith(
                        new ExactSequenceSecureRandom(knownCek, knownIv), binaryPayload()
                );
                WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
                parsedIv = parsed.iv();
                if (!Arrays.equals(knownIv, parsedIv)) {
                    throw new AssertionError("deterministic sender did not use the expected IV");
                }

                OuterBinding.Hashes correct = new OuterBinding().compute(
                        parsed.protectedHeader(), parsed.recipients()
                );
                protectedHash = correct.protectedHash();
                recipientsHash = correct.recipientsHash();
                if (target == BindingTarget.PROTECTED) {
                    protectedHash[0] ^= 1;
                } else {
                    recipientsHash[0] ^= 1;
                }

                innerBytes = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                        MESSAGE_ID,
                        TIMESTAMP,
                        binaryPayload(),
                        new OuterBinding.Hashes(protectedHash, recipientsHash)
                ));
                gcmAad = new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad());
                AeadCiphertext encrypted = gcm.encrypt(knownCek, parsedIv, gcmAad, innerBytes);
                WindLetter malicious = new WindLetter(
                        parsed.protectedHeader(),
                        parsed.protectedValue(),
                        parsed.aad(),
                        parsed.recipients(),
                        parsedIv,
                        encrypted.ciphertext(),
                        encrypted.tag()
                );
                return new JacksonOuterWireWriter().write(malicious);
            } finally {
                clear(knownCek);
                clear(knownIv);
                clear(protectedHash);
                clear(recipientsHash);
                clear(innerBytes);
                clear(gcmAad);
                clear(parsedIv);
            }
        }

        private String sendWith(SecureRandom random, ProtocolPayload payload) {
            PublicX25519UnsignedSender sender = new PublicX25519UnsignedSender(
                    new PublicX25519RecipientBuilder(kekDeriver, keyWrap), gcm, random
            );
            return sendWith(sender, payload);
        }

        private String sendWith(PublicX25519UnsignedSender sender, ProtocolPayload payload) {
            return sender.send(new PublicX25519UnsignedSender.Request(
                    payload,
                    MESSAGE_ID,
                    TIMESTAMP,
                    senderKey,
                    List.of(
                            firstRecipient.publicKey(),
                            secondRecipient.publicKey(),
                            thirdRecipient.publicKey()
                    )
            )).wireJson();
        }

        @Override
        public void close() {
            unrelatedRecipient.close();
            thirdRecipient.close();
            secondRecipient.close();
            firstRecipient.close();
            senderKey.close();
        }
    }

    private static final class ExactSequenceSecureRandom extends SecureRandom {

        private final List<byte[]> values;
        private int index;

        private ExactSequenceSecureRandom(byte[]... values) {
            this.values = Arrays.stream(values).map(byte[]::clone).toList();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if (index >= values.size()) {
                throw new AssertionError("sender requested more deterministic random values than expected");
            }
            byte[] value = values.get(index++);
            try {
                if (value.length != bytes.length) {
                    throw new AssertionError("sender requested an unexpected deterministic random length");
                }
                System.arraycopy(value, 0, bytes, 0, bytes.length);
            } finally {
                clear(value);
            }
        }
    }

    private static byte[] filled(int size, int value) {
        byte[] bytes = new byte[size];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
