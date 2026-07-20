package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
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
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
        byte[] testOwnedCanonicalRecipients =
                JcsCanonicalizer.canonicalize(root.get("recipients"));
        try {
            root.put("aad", Base64Url.encode(testOwnedCanonicalRecipients));
        } finally {
            clear(testOwnedCanonicalRecipients);
        }
    }

    static String protectedField(String wire, String name, String value) {
        ObjectNode root = object(wire);
        byte[] testOwnedProtected = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        byte[] testOwnedCanonicalProtected = null;
        try {
            ObjectNode header = object(new String(
                    testOwnedProtected, StandardCharsets.UTF_8
            ));
            header.put(name, value);
            testOwnedCanonicalProtected = JcsCanonicalizer.canonicalize(header);
            root.put("protected", Base64Url.encode(testOwnedCanonicalProtected));
            return json(root);
        } finally {
            clear(testOwnedProtected);
            clear(testOwnedCanonicalProtected);
        }
    }

    static String replaceEpkX(String wire, byte[] replacement) {
        ObjectNode root = object(wire);
        byte[] testOwnedProtected = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        byte[] testOwnedCanonicalProtected = null;
        try {
            ObjectNode header = object(new String(
                    testOwnedProtected, StandardCharsets.UTF_8
            ));
            ((ObjectNode) header.get("epk")).put("x", Base64Url.encode(replacement));
            testOwnedCanonicalProtected = JcsCanonicalizer.canonicalize(header);
            root.put("protected", Base64Url.encode(testOwnedCanonicalProtected));
            return json(root);
        } finally {
            clear(testOwnedProtected);
            clear(testOwnedCanonicalProtected);
        }
    }

    static void flipEncodedField(ObjectNode node, String fieldName) {
        byte[] testOwnedValue = Base64Url.decodeCanonical(
                node.get(fieldName).textValue(), "test." + fieldName
        );
        try {
            testOwnedValue[0] ^= 1;
            node.put(fieldName, Base64Url.encode(testOwnedValue));
        } finally {
            clear(testOwnedValue);
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
        final String unrelatedSigningKid = deriveSigningKid(unrelatedSigning);

        ProtocolPayload binaryPayload() {
            return new ProtocolPayload("application/octet-stream", BINARY, BINARY.length);
        }

        ProtocolPayload textPayload() {
            byte[] testOwnedText = "WindLetter 文本".getBytes(StandardCharsets.UTF_8);
            try {
                return new ProtocolPayload(
                        "text/plain; charset=utf-8",
                        testOwnedText,
                        testOwnedText.length
                );
            } finally {
                clear(testOwnedText);
            }
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
            byte[] testOwnedPublicKey = senderSigning.publicKey();
            try {
                return new TrustedEd25519Key(
                        IDENTITY_ID, signingKid, testOwnedPublicKey
                );
            } finally {
                clear(testOwnedPublicKey);
            }
        }

        String send(ProtocolPayload payload) {
            return send(payload, List.of(first, second, third));
        }

        String sendSigned(ProtocolPayload payload) {
            return sendSigned(payload, List.of(first, second, third));
        }

        String send(
                ProtocolPayload payload,
                List<X25519PrivateKeyHandle> recipientHandles
        ) {
            List<byte[]> testOwnedPublicKeys = publicKeys(recipientHandles);
            ProductionRawReferenceRandom productionRandom =
                    new ProductionRawReferenceRandom();
            ProductionRawReferenceGcm productionGcm =
                    new ProductionRawReferenceGcm(gcm);
            try {
                String wire = new ObfuscationX25519UnsignedSender(
                        builder(), productionGcm, productionRandom
                ).send(new ObfuscationX25519UnsignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, testOwnedPublicKeys
                )).wireJson();
                assertProductionSenderCleared(productionRandom, productionGcm);
                return wire;
            } finally {
                clearAll(testOwnedPublicKeys);
            }
        }

        String sendSigned(
                ProtocolPayload payload,
                List<X25519PrivateKeyHandle> recipientHandles
        ) {
            List<byte[]> testOwnedPublicKeys = publicKeys(recipientHandles);
            ProductionRawReferenceRandom productionRandom =
                    new ProductionRawReferenceRandom();
            ProductionRawReferenceGcm productionGcm =
                    new ProductionRawReferenceGcm(gcm);
            try {
                String wire = new ObfuscationX25519SignedSender(
                        builder(), productionGcm, ed25519, productionRandom
                ).send(new ObfuscationX25519SignedSender.Request(
                        payload, MESSAGE_ID, TIMESTAMP, senderSigning,
                        testOwnedPublicKeys
                )).wireJson();
                assertProductionSenderCleared(productionRandom, productionGcm);
                return wire;
            } finally {
                clearAll(testOwnedPublicKeys);
            }
        }

        List<X25519PrivateKeyHandle> newRecipientHandles(int count) {
            ArrayList<X25519PrivateKeyHandle> handles = new ArrayList<>(count);
            try {
                for (int index = 0; index < count; index++) {
                    handles.add(x25519.generatePrivateKey());
                }
                return List.copyOf(handles);
            } catch (RuntimeException failure) {
                closeHandles(handles);
                throw failure;
            }
        }

        List<RealRecipientPosition> realRecipientsInWireOrder(
                String wire,
                List<X25519PrivateKeyHandle> handles
        ) {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            Epk epk = (Epk) parsed.protectedHeader().senderInfo();
            byte[] testOwnedEpk = epk.x();
            ArrayList<RealRecipientPosition> positions = new ArrayList<>(handles.size());
            try {
                ObfuscationX25519KeyDeriver deriver =
                        new ObfuscationX25519KeyDeriver(x25519, hkdf);
                for (X25519PrivateKeyHandle handle : handles) {
                    byte[] testOwnedTargetRid = null;
                    try (ObfuscationX25519KeyDeriver.DerivedMaterial material =
                                 deriver.derive(handle, testOwnedEpk)) {
                        testOwnedTargetRid = material.rid();
                        int match = -1;
                        int matches = 0;
                        for (int wireIndex = 0;
                             wireIndex < parsed.recipients().size(); wireIndex++) {
                            RecipientEntry entry = parsed.recipients().get(wireIndex);
                            ObfuscationRecipient recipient =
                                    (ObfuscationRecipient) entry;
                            byte[] testOwnedWireRid = recipient.rid();
                            try {
                                if (MessageDigest.isEqual(
                                        testOwnedTargetRid, testOwnedWireRid
                                )) {
                                    match = wireIndex;
                                    matches++;
                                }
                            } finally {
                                clear(testOwnedWireRid);
                            }
                        }
                        assertEquals(1, matches,
                                "each real recipient rid must occur exactly once");
                        positions.add(new RealRecipientPosition(match, handle));
                    } finally {
                        clear(testOwnedTargetRid);
                    }
                }
                positions.sort(Comparator.comparingInt(
                        RealRecipientPosition::wireIndex
                ));
                return List.copyOf(positions);
            } finally {
                clear(testOwnedEpk);
            }
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
            byte[] testOwnedCek = recovery().recover(
                    (com.windletter.protocol.wire.Epk) parsed.protectedHeader().senderInfo(),
                    parsed.recipients(), List.of(second)
            );
            byte[] testOwnedAad = new OuterAad().gcmInput(
                    parsed.protectedValue(), parsed.aad()
            );
            byte[] testOwnedIv = parsed.iv();
            byte[] testOwnedCiphertext = null;
            byte[] testOwnedTag = null;
            try {
                AeadCiphertext encrypted = gcm.encrypt(
                        testOwnedCek, testOwnedIv, testOwnedAad, innerBytes
                );
                testOwnedCiphertext = encrypted.ciphertext();
                testOwnedTag = encrypted.tag();
                return new JacksonOuterWireWriter().write(new WindLetter(
                        parsed.protectedHeader(), parsed.protectedValue(), parsed.aad(),
                        parsed.recipients(), testOwnedIv,
                        testOwnedCiphertext, testOwnedTag
                ));
            } finally {
                clear(testOwnedCek);
                clear(testOwnedAad);
                clear(testOwnedIv);
                clear(testOwnedCiphertext);
                clear(testOwnedTag);
            }
        }

        String bindingFailure(String originalWire) {
            byte[] testOwnedWrongProtectedHash = new byte[32];
            byte[] testOwnedWrongRecipientsHash = new byte[32];
            byte[] inner = new UnsignedInnerCodec().encode(
                    new UnsignedInnerCodec.Message(
                            MESSAGE_ID, TIMESTAMP, binaryPayload(),
                            new OuterBinding.Hashes(
                                    testOwnedWrongProtectedHash,
                                    testOwnedWrongRecipientsHash
                            )
                    )
            );
            try {
                return authenticatedWire(originalWire, inner);
            } finally {
                clear(testOwnedWrongProtectedHash);
                clear(testOwnedWrongRecipientsHash);
                clear(inner);
            }
        }

        String signedBindingFailure(String originalWire) {
            byte[] testOwnedWrongProtectedHash = new byte[32];
            byte[] testOwnedWrongRecipientsHash = new byte[32];
            try {
                return authenticatedSignedWire(
                        originalWire,
                        new OuterBinding.Hashes(
                                testOwnedWrongProtectedHash,
                                testOwnedWrongRecipientsHash
                        ),
                        signingKid,
                        senderSigning
                );
            } finally {
                clear(testOwnedWrongProtectedHash);
                clear(testOwnedWrongRecipientsHash);
            }
        }

        String authenticatedSignedWire(
                String originalWire,
                OuterBinding.Hashes binding,
                String kid,
                Ed25519PrivateKeyHandle signingKey
        ) {
            byte[] testOwnedInner = signedInner(binding, kid, signingKey);
            try {
                return authenticatedWire(originalWire, testOwnedInner);
            } finally {
                clear(testOwnedInner);
            }
        }

        String authenticatedFlippedSignature(String originalWire) {
            byte[] testOwnedValidInner = validSignedInner(
                    originalWire, signingKid, senderSigning
            );
            byte[] testOwnedSignature = null;
            byte[] testOwnedMaliciousInner = null;
            try {
                ObjectNode inner = object(new String(
                        testOwnedValidInner, StandardCharsets.UTF_8
                ));
                testOwnedSignature = Base64Url.decodeCanonical(
                        inner.get("signature").textValue(), "test.inner.signature"
                );
                testOwnedSignature[0] ^= 1;
                inner.put("signature", Base64Url.encode(testOwnedSignature));
                testOwnedMaliciousInner = JcsCanonicalizer.canonicalize(inner);
                return authenticatedWire(originalWire, testOwnedMaliciousInner);
            } finally {
                clear(testOwnedValidInner);
                clear(testOwnedSignature);
                clear(testOwnedMaliciousInner);
            }
        }

        String authenticatedUnknownSigner(String originalWire) {
            WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
            return authenticatedSignedWire(
                    originalWire,
                    new OuterBinding().compute(
                            parsed.protectedHeader(), parsed.recipients()
                    ),
                    unrelatedSigningKid,
                    unrelatedSigning
            );
        }

        String authenticatedChangedSignedSegment(
                String originalWire,
                String segment
        ) {
            if (!"protected".equals(segment) && !"payload".equals(segment)) {
                throw new IllegalArgumentException(
                        "segment must be protected or payload"
                );
            }
            byte[] testOwnedValidInner = validSignedInner(
                    originalWire, signingKid, senderSigning
            );
            byte[] testOwnedSegment = null;
            byte[] testOwnedCanonicalSegment = null;
            byte[] testOwnedMaliciousInner = null;
            try {
                ObjectNode inner = object(new String(
                        testOwnedValidInner, StandardCharsets.UTF_8
                ));
                testOwnedSegment = Base64Url.decodeCanonical(
                        inner.get(segment).textValue(), "test.inner." + segment
                );
                ObjectNode decoded = object(new String(
                        testOwnedSegment, StandardCharsets.UTF_8
                ));
                if ("protected".equals(segment)) {
                    decoded.put("ts", TIMESTAMP + 1);
                } else {
                    ((ObjectNode) decoded.get("meta")).put(
                            "content_type",
                            "application/vnd.windletter.changed+binary"
                    );
                }
                testOwnedCanonicalSegment = JcsCanonicalizer.canonicalize(decoded);
                inner.put(segment, Base64Url.encode(testOwnedCanonicalSegment));
                testOwnedMaliciousInner = JcsCanonicalizer.canonicalize(inner);
                return authenticatedWire(originalWire, testOwnedMaliciousInner);
            } finally {
                clear(testOwnedValidInner);
                clear(testOwnedSegment);
                clear(testOwnedCanonicalSegment);
                clear(testOwnedMaliciousInner);
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

        private byte[] validSignedInner(
                String originalWire,
                String kid,
                Ed25519PrivateKeyHandle signingKey
        ) {
            WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
            return signedInner(
                    new OuterBinding().compute(
                            parsed.protectedHeader(), parsed.recipients()
                    ),
                    kid,
                    signingKey
            );
        }

        private byte[] signedInner(
                OuterBinding.Hashes binding,
                String kid,
                Ed25519PrivateKeyHandle signingKey
        ) {
            byte[] testOwnedSigningInput = null;
            byte[] testOwnedSignature = null;
            try (SignedInnerCodec.Prepared prepared =
                         new SignedInnerCodec().prepare(new SignedInnerCodec.Message(
                                 MESSAGE_ID, TIMESTAMP, binaryPayload(), binding, kid
                         ))) {
                testOwnedSigningInput = prepared.signingInput();
                testOwnedSignature = ed25519.sign(
                        signingKey, testOwnedSigningInput
                );
                return new SignedInnerCodec().assemble(
                        prepared, testOwnedSignature
                );
            } finally {
                clear(testOwnedSigningInput);
                clear(testOwnedSignature);
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

        private static List<byte[]> publicKeys(
                List<X25519PrivateKeyHandle> handles
        ) {
            ArrayList<byte[]> publicKeys = new ArrayList<>(handles.size());
            try {
                for (X25519PrivateKeyHandle handle : handles) {
                    publicKeys.add(handle.publicKey());
                }
                return publicKeys;
            } catch (RuntimeException failure) {
                clearAll(publicKeys);
                throw failure;
            }
        }

        private static void assertProductionSenderCleared(
                ProductionRawReferenceRandom random,
                ProductionRawReferenceGcm gcm
        ) {
            assertEquals(2, random.productionRawReferences.size());
            assertEquals(4, gcm.productionRawReferences.size());
            for (byte[] reference : random.productionRawReferences) {
                assertNotNull(reference);
                assertTrue(allZero(reference),
                        "sender-owned random output was not cleared");
            }
            for (byte[] reference : gcm.productionRawReferences) {
                assertNotNull(reference);
                assertTrue(allZero(reference),
                        "sender-owned GCM input was not cleared");
            }
        }
    }

    record RealRecipientPosition(
            int wireIndex,
            X25519PrivateKeyHandle handle
    ) {
    }

    static void closeHandles(List<X25519PrivateKeyHandle> handles) {
        for (int index = handles.size() - 1; index >= 0; index--) {
            handles.get(index).close();
        }
    }

    private static void clearAll(List<byte[]> values) {
        if (values != null) {
            for (byte[] value : values) clear(value);
        }
    }

    private static final class ProductionRawReferenceRandom extends SecureRandom {
        private final SecureRandom delegate = new SecureRandom();
        private final ArrayList<byte[]> productionRawReferences = new ArrayList<>();

        @Override
        public void nextBytes(byte[] bytes) {
            delegate.nextBytes(bytes);
            productionRawReferences.add(bytes);
        }
    }

    private static final class ProductionRawReferenceGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final ArrayList<byte[]> productionRawReferences = new ArrayList<>();

        private ProductionRawReferenceGcm(A256GcmCrypto delegate) {
            this.delegate = delegate;
        }

        @Override
        public AeadCiphertext encrypt(
                byte[] key,
                byte[] iv,
                byte[] aad,
                byte[] plaintext
        ) {
            productionRawReferences.add(key);
            productionRawReferences.add(iv);
            productionRawReferences.add(aad);
            productionRawReferences.add(plaintext);
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key,
                byte[] iv,
                byte[] aad,
                byte[] ciphertext,
                byte[] tag
        ) {
            return delegate.decrypt(key, iv, aad, ciphertext, tag);
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
