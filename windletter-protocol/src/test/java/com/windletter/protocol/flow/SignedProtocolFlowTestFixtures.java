package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicX25519RecipientBuilder;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.WindLetter;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

final class SignedProtocolFlowTestFixtures implements AutoCloseable {

    static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    static final long TIMESTAMP = 1_731_800_000L;
    static final String CONTENT_TYPE = "application/vnd.windletter.test+binary";
    static final String IDENTITY_ID = "sender-identity-1";
    static final byte[] BINARY_PAYLOAD = {0x00, 0x01, 0x7f, (byte) 0x80, (byte) 0xff, 0x42};

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int KNOWN_CEK_BYTE = 0x51;
    private static final int KNOWN_IV_BYTE = 0x61;

    final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
    final PublicX25519KekDeriver kekDeriver = new PublicX25519KekDeriver(
            x25519, new BouncyCastleHkdfCrypto()
    );
    final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
    final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
    final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
    final X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
    final Ed25519PrivateKeyHandle senderSigningKey = ed25519.generatePrivateKey();
    final Ed25519PrivateKeyHandle unrelatedSigningKey = ed25519.generatePrivateKey();
    final X25519PrivateKeyHandle firstRecipient = x25519.generatePrivateKey();
    final X25519PrivateKeyHandle secondRecipient = x25519.generatePrivateKey();
    final X25519PrivateKeyHandle thirdRecipient = x25519.generatePrivateKey();
    final X25519PrivateKeyHandle unrelatedRecipient = x25519.generatePrivateKey();

    final String senderEncryptionKid;
    final String signingKid;

    SignedProtocolFlowTestFixtures() {
        byte[] encryptionPublicKey = senderEncryptionKey.publicKey();
        byte[] signingPublicKey = senderSigningKey.publicKey();
        try {
            senderEncryptionKid = X25519KeyId.derive(encryptionPublicKey);
            signingKid = Ed25519KeyId.derive(signingPublicKey);
        } finally {
            clear(encryptionPublicKey);
            clear(signingPublicKey);
        }
    }

    ProtocolPayload binaryPayload() {
        return new ProtocolPayload(CONTENT_TYPE, BINARY_PAYLOAD, BINARY_PAYLOAD.length);
    }

    ProtocolPayload emptyPayload() {
        return new ProtocolPayload(CONTENT_TYPE, new byte[0], 0);
    }

    List<X25519PrivateKeyHandle> recipients() {
        return List.of(firstRecipient, secondRecipient, thirdRecipient);
    }

    String send(ProtocolPayload payload) {
        return sender(new SecureRandom()).send(sendRequest(payload)).wireJson();
    }

    PublicX25519SignedReceiver receiver() {
        return new PublicX25519SignedReceiver(kekDeriver, keyWrap, gcm, ed25519);
    }

    PublicX25519SignedReceiver.Request receiveRequest(
            String wireJson,
            X25519PrivateKeyHandle recipient
    ) {
        return receiveRequest(wireJson, recipient, trustedSigningResolver());
    }

    PublicX25519SignedReceiver.Request receiveRequest(
            String wireJson,
            X25519PrivateKeyHandle recipient,
            Ed25519VerificationKeyResolver signingResolver
    ) {
        return new PublicX25519SignedReceiver.Request(
                wireJson,
                requestedKid -> senderEncryptionKid.equals(requestedKid)
                        ? Optional.of(senderEncryptionKey.publicKey())
                        : Optional.empty(),
                signingResolver,
                List.of(recipient)
        );
    }

    Ed25519VerificationKeyResolver trustedSigningResolver() {
        return requestedKid -> signingKid.equals(requestedKid)
                ? Optional.of(trustedSigningKey())
                : Optional.empty();
    }

    TrustedEd25519Key trustedSigningKey() {
        return new TrustedEd25519Key(IDENTITY_ID, signingKid, senderSigningKey.publicKey());
    }

    String authenticatedBindingTamper(ProtocolFlowTestFixtures.BindingTarget target) {
        return authenticatedMutation(context -> {
            OuterBinding.Hashes correct = new OuterBinding().compute(
                    context.parsed().protectedHeader(), context.parsed().recipients()
            );
            byte[] protectedHash = correct.protectedHash();
            byte[] recipientsHash = correct.recipientsHash();
            byte[] inner = null;
            try {
                if (target == ProtocolFlowTestFixtures.BindingTarget.PROTECTED) {
                    protectedHash[0] ^= 1;
                } else {
                    recipientsHash[0] ^= 1;
                }
                inner = signedInner(
                        new OuterBinding.Hashes(protectedHash, recipientsHash),
                        senderSigningKey,
                        signingKid,
                        binaryPayload()
                );
                return reencrypt(context, inner);
            } finally {
                clear(protectedHash);
                clear(recipientsHash);
                clear(inner);
            }
        });
    }

    String authenticatedFlippedSignature() {
        return mutateValidSignedRoot(root -> {
            byte[] signature = Base64Url.decodeCanonical(
                    root.get("signature").textValue(), "test.inner.signature"
            );
            try {
                signature[0] ^= 1;
                root.put("signature", Base64Url.encode(signature));
            } finally {
                clear(signature);
            }
        });
    }

    String authenticatedChangedSegment(String segment) {
        if (!"protected".equals(segment) && !"payload".equals(segment)) {
            throw new IllegalArgumentException("segment must be protected or payload");
        }
        return mutateValidSignedRoot(root -> {
            byte[] original = Base64Url.decodeCanonical(
                    root.get(segment).textValue(), "test.inner." + segment
            );
            try {
                ObjectNode decodedSegment = parseObject(original);
                if ("protected".equals(segment)) {
                    decodedSegment.put("ts", TIMESTAMP + 1);
                } else {
                    ObjectNode meta = (ObjectNode) decodedSegment.get("meta");
                    meta.put("content_type", CONTENT_TYPE + ";tampered=true");
                }
                root.put(segment, Base64Url.encode(JcsCanonicalizer.canonicalize(decodedSegment)));
            } finally {
                clear(original);
            }
        });
    }

    String authenticatedUnknownSigner() {
        return authenticatedMutation(context -> {
            OuterBinding.Hashes binding = new OuterBinding().compute(
                    context.parsed().protectedHeader(), context.parsed().recipients()
            );
            byte[] unrelatedPublicKey = unrelatedSigningKey.publicKey();
            byte[] inner = null;
            try {
                String unrelatedKid = Ed25519KeyId.derive(unrelatedPublicKey);
                inner = signedInner(
                        binding, unrelatedSigningKey, unrelatedKid, binaryPayload()
                );
                return reencrypt(context, inner);
            } finally {
                clear(unrelatedPublicKey);
                clear(inner);
            }
        });
    }

    String authenticatedUnsignedInner() {
        return authenticatedMutation(context -> {
            byte[] inner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    MESSAGE_ID,
                    TIMESTAMP,
                    binaryPayload(),
                    new OuterBinding().compute(
                            context.parsed().protectedHeader(), context.parsed().recipients()
                    )
            ));
            try {
                return reencrypt(context, inner);
            } finally {
                clear(inner);
            }
        });
    }

    String authenticatedWrongProtectedField(String field, String value) {
        return mutateValidSignedRoot(root -> {
            byte[] protectedBytes = Base64Url.decodeCanonical(
                    root.get("protected").textValue(), "test.inner.protected"
            );
            try {
                ObjectNode protectedNode = parseObject(protectedBytes);
                protectedNode.put(field, value);
                root.put("protected", Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode)));
            } finally {
                clear(protectedBytes);
            }
        });
    }

    String authenticatedMissingRootField(String field) {
        return mutateValidSignedRoot(root -> root.remove(field));
    }

    String authenticatedExtraRootField() {
        return mutateValidSignedRoot(root -> root.put("unexpected", true));
    }

    String authenticatedBadKidLength(int length) {
        return authenticatedWrongProtectedField("kid", Base64Url.encode(new byte[length]));
    }

    String authenticatedBadSignatureLength(int length) {
        return mutateValidSignedRoot(root -> root.put("signature", Base64Url.encode(new byte[length])));
    }

    private String mutateValidSignedRoot(Consumer<ObjectNode> mutation) {
        return authenticatedMutation(context -> {
            OuterBinding.Hashes binding = new OuterBinding().compute(
                    context.parsed().protectedHeader(), context.parsed().recipients()
            );
            byte[] validInner = null;
            byte[] maliciousInner = null;
            try {
                validInner = signedInner(binding, senderSigningKey, signingKid, binaryPayload());
                ObjectNode root = parseObject(validInner);
                mutation.accept(root);
                maliciousInner = JcsCanonicalizer.canonicalize(root);
                return reencrypt(context, maliciousInner);
            } finally {
                clear(validInner);
                clear(maliciousInner);
            }
        });
    }

    private String authenticatedMutation(AuthenticatedMutation mutation) {
        byte[] knownCek = filled(32, KNOWN_CEK_BYTE);
        byte[] knownIv = filled(12, KNOWN_IV_BYTE);
        try {
            String originalWire = sender(new ExactSequenceSecureRandom(knownCek, knownIv))
                    .send(sendRequest(binaryPayload()))
                    .wireJson();
            WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
            byte[] parsedIv = parsed.iv();
            try {
                if (!Arrays.equals(knownIv, parsedIv)) {
                    throw new AssertionError("deterministic signed sender did not use expected IV");
                }
            } finally {
                clear(parsedIv);
            }
            return mutation.apply(new AuthenticatedContext(parsed, knownCek));
        } finally {
            clear(knownCek);
            clear(knownIv);
        }
    }

    private byte[] signedInner(
            OuterBinding.Hashes binding,
            Ed25519PrivateKeyHandle signingKey,
            String kid,
            ProtocolPayload payload
    ) {
        SignedInnerCodec codec = new SignedInnerCodec();
        byte[] signingInput = null;
        byte[] signature = null;
        try (SignedInnerCodec.Prepared prepared = codec.prepare(new SignedInnerCodec.Message(
                MESSAGE_ID, TIMESTAMP, payload, binding, kid
        ))) {
            signingInput = prepared.signingInput();
            signature = ed25519.sign(signingKey, signingInput);
            return codec.assemble(prepared, signature);
        } finally {
            clear(signingInput);
            clear(signature);
        }
    }

    private String reencrypt(AuthenticatedContext context, byte[] inner) {
        byte[] gcmAad = new OuterAad().gcmInput(
                context.parsed().protectedValue(), context.parsed().aad()
        );
        byte[] iv = context.parsed().iv();
        try {
            AeadCiphertext encrypted = gcm.encrypt(context.cek(), iv, gcmAad, inner);
            WindLetter malicious = new WindLetter(
                    context.parsed().protectedHeader(),
                    context.parsed().protectedValue(),
                    context.parsed().aad(),
                    context.parsed().recipients(),
                    iv,
                    encrypted.ciphertext(),
                    encrypted.tag()
            );
            return new JacksonOuterWireWriter().write(malicious);
        } finally {
            clear(gcmAad);
            clear(iv);
        }
    }

    private PublicX25519SignedSender sender(SecureRandom random) {
        return new PublicX25519SignedSender(
                new PublicX25519RecipientBuilder(kekDeriver, keyWrap),
                gcm,
                ed25519,
                random
        );
    }

    private PublicX25519SignedSender.Request sendRequest(ProtocolPayload payload) {
        return new PublicX25519SignedSender.Request(
                payload,
                MESSAGE_ID,
                TIMESTAMP,
                senderEncryptionKey,
                senderSigningKey,
                List.of(
                        firstRecipient.publicKey(),
                        secondRecipient.publicKey(),
                        thirdRecipient.publicKey()
                )
        );
    }

    private static ObjectNode parseObject(byte[] json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (Exception e) {
            throw new AssertionError("failed to parse test JSON", e);
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

    @Override
    public void close() {
        unrelatedRecipient.close();
        thirdRecipient.close();
        secondRecipient.close();
        firstRecipient.close();
        unrelatedSigningKey.close();
        senderSigningKey.close();
        senderEncryptionKey.close();
    }

    private record AuthenticatedContext(WindLetter parsed, byte[] cek) {
    }

    @FunctionalInterface
    private interface AuthenticatedMutation {
        String apply(AuthenticatedContext context);
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
                    throw new AssertionError("sender requested unexpected deterministic random length");
                }
                System.arraycopy(value, 0, bytes, 0, bytes.length);
            } finally {
                clear(value);
            }
        }
    }
}
