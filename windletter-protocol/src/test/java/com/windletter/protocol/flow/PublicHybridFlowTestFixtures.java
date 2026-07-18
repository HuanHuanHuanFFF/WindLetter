package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicHybridRecipientBuilder;
import com.windletter.protocol.recipient.PublicHybridRecipientKeys;
import com.windletter.protocol.routing.PublicHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

final class PublicHybridFlowTestFixtures implements AutoCloseable {

    static final String IDENTITY_ID = "hybrid-sender-identity-1";

    private static final ObjectMapper JSON = new ObjectMapper();

    final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
    final BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
    final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
    final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
    final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
    final PublicHybridKekDeriver kekDeriver = new PublicHybridKekDeriver(
            x25519, mlkem, new BouncyCastleHkdfCrypto()
    );

    final X25519PrivateKeyHandle senderEncryptionKey = x25519.generatePrivateKey();
    final Ed25519PrivateKeyHandle senderSigningKey = ed25519.generatePrivateKey();
    final Ed25519PrivateKeyHandle unrelatedSigningKey = ed25519.generatePrivateKey();
    final HybridPair first = new HybridPair(
            x25519.generatePrivateKey(), mlkem.generatePrivateKey()
    );
    final HybridPair middle = new HybridPair(
            x25519.generatePrivateKey(), mlkem.generatePrivateKey()
    );
    final HybridPair last = new HybridPair(
            x25519.generatePrivateKey(), mlkem.generatePrivateKey()
    );
    final HybridPair unrelated = new HybridPair(
            x25519.generatePrivateKey(), mlkem.generatePrivateKey()
    );

    final String senderEncryptionKid;
    final String signingKid;
    final String unrelatedSigningKid;

    PublicHybridFlowTestFixtures() {
        byte[] senderPublic = senderEncryptionKey.publicKey();
        byte[] signingPublic = senderSigningKey.publicKey();
        byte[] unrelatedSigningPublic = unrelatedSigningKey.publicKey();
        try {
            senderEncryptionKid = X25519KeyId.derive(senderPublic);
            signingKid = Ed25519KeyId.derive(signingPublic);
            unrelatedSigningKid = Ed25519KeyId.derive(unrelatedSigningPublic);
        } finally {
            clear(senderPublic);
            clear(signingPublic);
            clear(unrelatedSigningPublic);
        }
    }

    ProtocolPayload binaryPayload() {
        return new ProtocolPayload(
                ProtocolFlowTestFixtures.CONTENT_TYPE,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD.length
        );
    }

    ProtocolPayload emptyPayload() {
        return new ProtocolPayload(
                ProtocolFlowTestFixtures.CONTENT_TYPE, new byte[0], 0
        );
    }

    List<HybridPair> recipients() {
        return List.of(first, middle, last);
    }

    String sendUnsigned(ProtocolPayload payload) {
        PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                new PublicHybridRecipientBuilder(kekDeriver, keyWrap), gcm
        );
        return sender.send(new PublicHybridUnsignedSender.Request(
                payload,
                ProtocolFlowTestFixtures.MESSAGE_ID,
                ProtocolFlowTestFixtures.TIMESTAMP,
                senderEncryptionKey,
                recipientPublicKeys()
        )).wireJson();
    }

    String sendSigned(ProtocolPayload payload) {
        PublicHybridSignedSender sender = new PublicHybridSignedSender(
                new PublicHybridRecipientBuilder(kekDeriver, keyWrap),
                gcm,
                ed25519
        );
        return sender.send(new PublicHybridSignedSender.Request(
                payload,
                ProtocolFlowTestFixtures.MESSAGE_ID,
                ProtocolFlowTestFixtures.TIMESTAMP,
                senderEncryptionKey,
                senderSigningKey,
                recipientPublicKeys()
        )).wireJson();
    }

    PublicHybridUnsignedReceiver unsignedReceiver() {
        return new PublicHybridUnsignedReceiver(kekDeriver, keyWrap, gcm);
    }

    PublicHybridSignedReceiver signedReceiver() {
        return signedReceiver(ed25519);
    }

    PublicHybridSignedReceiver signedReceiver(Ed25519Crypto verifier) {
        return new PublicHybridSignedReceiver(kekDeriver, keyWrap, gcm, verifier);
    }

    PublicHybridUnsignedReceiver.Request unsignedRequest(
            String wire,
            HybridPair recipient
    ) {
        return new PublicHybridUnsignedReceiver.Request(
                wire,
                requestedKid -> senderEncryptionKid.equals(requestedKid)
                        ? Optional.of(senderEncryptionKey.publicKey())
                        : Optional.empty(),
                List.of(recipient.privateKeys())
        );
    }

    PublicHybridSignedReceiver.Request signedRequest(
            String wire,
            HybridPair recipient
    ) {
        return signedRequest(wire, recipient, trustedSigningResolver());
    }

    PublicHybridSignedReceiver.Request signedRequest(
            String wire,
            HybridPair recipient,
            Ed25519VerificationKeyResolver signingResolver
    ) {
        return new PublicHybridSignedReceiver.Request(
                wire,
                requestedKid -> senderEncryptionKid.equals(requestedKid)
                        ? Optional.of(senderEncryptionKey.publicKey())
                        : Optional.empty(),
                signingResolver,
                List.of(recipient.privateKeys())
        );
    }

    Ed25519VerificationKeyResolver trustedSigningResolver() {
        return requestedKid -> signingKid.equals(requestedKid)
                ? Optional.of(trustedSigningKey())
                : Optional.empty();
    }

    TrustedEd25519Key trustedSigningKey() {
        return new TrustedEd25519Key(
                IDENTITY_ID, signingKid, senderSigningKey.publicKey()
        );
    }

    void assertThreeRecipientWire(String wire) {
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        assertEquals(3, parsed.recipients().size());
        byte[][] encapsulations = new byte[3][];
        String[] combinedKids = new String[3];
        try {
            for (int index = 0; index < recipients().size(); index++) {
                HybridPair pair = recipients().get(index);
                PublicRecipient entry = assertInstanceOf(
                        PublicRecipient.class, parsed.recipients().get(index)
                );
                byte[] x25519Public = pair.x25519.publicKey();
                byte[] mlkemPublic = pair.mlkem768.publicKey();
                byte[] wrappedCek = entry.encryptedKey();
                try {
                    assertEquals(X25519KeyId.derive(x25519Public), entry.kid().x25519());
                    assertEquals(MLKem768KeyId.derive(mlkemPublic), entry.kid().mlkem768());
                    assertEquals(40, wrappedCek.length);
                    encapsulations[index] = entry.ek();
                    assertEquals(1088, encapsulations[index].length);
                    combinedKids[index] = entry.kid().x25519() + ":" + entry.kid().mlkem768();
                } finally {
                    clear(x25519Public);
                    clear(mlkemPublic);
                    clear(wrappedCek);
                }
            }
            assertFalse(Arrays.equals(encapsulations[0], encapsulations[1]));
            assertFalse(Arrays.equals(encapsulations[0], encapsulations[2]));
            assertFalse(Arrays.equals(encapsulations[1], encapsulations[2]));
            assertNotEquals(combinedKids[0], combinedKids[1]);
            assertNotEquals(combinedKids[0], combinedKids[2]);
            assertNotEquals(combinedKids[1], combinedKids[2]);
            assertEquals(new OuterAad().compute(parsed.recipients()), parsed.aad());
        } finally {
            for (byte[] encapsulation : encapsulations) {
                clear(encapsulation);
            }
        }
    }

    String replaceTargetEkWithUnrelatedRealEncapsulation(
            String wire,
            int targetIndex
    ) {
        byte[] unrelatedPublic = unrelated.mlkem768.publicKey();
        byte[] ciphertext = null;
        try (MLKem768Encapsulation encapsulation = mlkem.encapsulate(unrelatedPublic)) {
            ciphertext = encapsulation.ciphertext();
            ObjectNode root = ProtocolFlowTestFixtures.parseObject(wire);
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(targetIndex);
            target.put("ek", Base64Url.encode(ciphertext));
            ProtocolFlowTestFixtures.recomputeAad(root);
            return ProtocolFlowTestFixtures.write(root);
        } finally {
            clear(unrelatedPublic);
            clear(ciphertext);
        }
    }

    String swapRealEncapsulations(String wire, int firstIndex, int secondIndex) {
        ObjectNode root = ProtocolFlowTestFixtures.parseObject(wire);
        ObjectNode firstRecipient = (ObjectNode) root.withArray("recipients").get(firstIndex);
        ObjectNode secondRecipient = (ObjectNode) root.withArray("recipients").get(secondIndex);
        String firstEk = firstRecipient.get("ek").textValue();
        firstRecipient.put("ek", secondRecipient.get("ek").textValue());
        secondRecipient.put("ek", firstEk);
        ProtocolFlowTestFixtures.recomputeAad(root);
        return ProtocolFlowTestFixtures.write(root);
    }

    String authenticatedUnsignedWrongBinding(
            String wire,
            HybridPair recipient,
            int recipientIndex
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        OuterBinding.Hashes correct = new OuterBinding().compute(
                parsed.protectedHeader(), parsed.recipients()
        );
        byte[] protectedHash = correct.protectedHash();
        byte[] recipientsHash = correct.recipientsHash();
        byte[] inner = null;
        try {
            protectedHash[0] ^= 1;
            inner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    ProtocolFlowTestFixtures.MESSAGE_ID,
                    ProtocolFlowTestFixtures.TIMESTAMP,
                    binaryPayload(),
                    new OuterBinding.Hashes(protectedHash, recipientsHash)
            ));
            return reencrypt(wire, recipient, recipientIndex, inner);
        } finally {
            clear(protectedHash);
            clear(recipientsHash);
            clear(inner);
        }
    }

    String authenticatedSignedWrongBinding(
            String wire,
            HybridPair recipient,
            int recipientIndex
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        OuterBinding.Hashes correct = new OuterBinding().compute(
                parsed.protectedHeader(), parsed.recipients()
        );
        byte[] protectedHash = correct.protectedHash();
        byte[] recipientsHash = correct.recipientsHash();
        byte[] inner = null;
        try {
            protectedHash[0] ^= 1;
            inner = signedInner(
                    new OuterBinding.Hashes(protectedHash, recipientsHash),
                    senderSigningKey,
                    signingKid
            );
            return reencrypt(wire, recipient, recipientIndex, inner);
        } finally {
            clear(protectedHash);
            clear(recipientsHash);
            clear(inner);
        }
    }

    String authenticatedFlippedSignature(
            String wire,
            HybridPair recipient,
            int recipientIndex
    ) {
        byte[] validInner = validSignedInner(wire, senderSigningKey, signingKid);
        byte[] signature = null;
        byte[] maliciousInner = null;
        try {
            ObjectNode root = parseObject(validInner);
            signature = Base64Url.decodeCanonical(
                    root.get("signature").textValue(), "test.inner.signature"
            );
            signature[0] ^= 1;
            root.put("signature", Base64Url.encode(signature));
            maliciousInner = JcsCanonicalizer.canonicalize(root);
            return reencrypt(wire, recipient, recipientIndex, maliciousInner);
        } finally {
            clear(validInner);
            clear(signature);
            clear(maliciousInner);
        }
    }

    String authenticatedUnknownRealSigner(
            String wire,
            HybridPair recipient,
            int recipientIndex
    ) {
        byte[] inner = validSignedInner(
                wire, unrelatedSigningKey, unrelatedSigningKid
        );
        try {
            return reencrypt(wire, recipient, recipientIndex, inner);
        } finally {
            clear(inner);
        }
    }

    String authenticatedChangedSignedSegment(
            String wire,
            HybridPair recipient,
            int recipientIndex,
            String segment
    ) {
        if (!"protected".equals(segment) && !"payload".equals(segment)) {
            throw new IllegalArgumentException("segment must be protected or payload");
        }
        byte[] validInner = validSignedInner(wire, senderSigningKey, signingKid);
        byte[] segmentBytes = null;
        byte[] maliciousInner = null;
        try {
            ObjectNode root = parseObject(validInner);
            segmentBytes = Base64Url.decodeCanonical(
                    root.get(segment).textValue(), "test.inner." + segment
            );
            ObjectNode decoded = parseObject(segmentBytes);
            if ("protected".equals(segment)) {
                decoded.put("ts", ProtocolFlowTestFixtures.TIMESTAMP + 1);
            } else {
                ((ObjectNode) decoded.get("meta")).put(
                        "content_type", "application/vnd.windletter.changed+binary"
                );
            }
            root.put(segment, Base64Url.encode(JcsCanonicalizer.canonicalize(decoded)));
            maliciousInner = JcsCanonicalizer.canonicalize(root);
            return reencrypt(wire, recipient, recipientIndex, maliciousInner);
        } finally {
            clear(validInner);
            clear(segmentBytes);
            clear(maliciousInner);
        }
    }

    private List<PublicHybridRecipientKeys> recipientPublicKeys() {
        return recipients().stream().map(HybridPair::publicKeys).toList();
    }

    private byte[] validSignedInner(
            String wire,
            Ed25519PrivateKeyHandle signingKey,
            String kid
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        return signedInner(
                new OuterBinding().compute(
                        parsed.protectedHeader(), parsed.recipients()
                ),
                signingKey,
                kid
        );
    }

    private byte[] signedInner(
            OuterBinding.Hashes binding,
            Ed25519PrivateKeyHandle signingKey,
            String kid
    ) {
        SignedInnerCodec codec = new SignedInnerCodec();
        byte[] signingInput = null;
        byte[] signature = null;
        try (SignedInnerCodec.Prepared prepared = codec.prepare(
                new SignedInnerCodec.Message(
                        ProtocolFlowTestFixtures.MESSAGE_ID,
                        ProtocolFlowTestFixtures.TIMESTAMP,
                        binaryPayload(),
                        binding,
                        kid
                )
        )) {
            signingInput = prepared.signingInput();
            signature = ed25519.sign(signingKey, signingInput);
            return codec.assemble(prepared, signature);
        } finally {
            clear(signingInput);
            clear(signature);
        }
    }

    private String reencrypt(
            String wire,
            HybridPair recipient,
            int recipientIndex,
            byte[] inner
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(wire);
        PublicRecipient entry = (PublicRecipient) parsed.recipients().get(recipientIndex);
        byte[] senderPublic = senderEncryptionKey.publicKey();
        byte[] ek = entry.ek();
        byte[] kek = null;
        byte[] encryptedKey = null;
        byte[] cek = null;
        byte[] aad = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] tag = null;
        try {
            kek = kekDeriver.deriveForReceiver(
                    recipient.x25519, senderPublic, recipient.mlkem768, ek
            );
            encryptedKey = entry.encryptedKey();
            cek = keyWrap.unwrap(kek, encryptedKey);
            aad = new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad());
            iv = parsed.iv();
            AeadCiphertext encrypted = gcm.encrypt(cek, iv, aad, inner);
            ciphertext = encrypted.ciphertext();
            tag = encrypted.tag();
            return new JacksonOuterWireWriter().write(new WindLetter(
                    parsed.protectedHeader(),
                    parsed.protectedValue(),
                    parsed.aad(),
                    parsed.recipients(),
                    iv,
                    ciphertext,
                    tag
            ));
        } finally {
            clear(senderPublic);
            clear(ek);
            clear(kek);
            clear(encryptedKey);
            clear(cek);
            clear(aad);
            clear(iv);
            clear(ciphertext);
            clear(tag);
        }
    }

    private static ObjectNode parseObject(byte[] json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (Exception e) {
            throw new AssertionError("failed to parse test JSON bytes", e);
        }
    }

    static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    @Override
    public void close() {
        unrelated.close();
        last.close();
        middle.close();
        first.close();
        unrelatedSigningKey.close();
        senderSigningKey.close();
        senderEncryptionKey.close();
    }

    static final class HybridPair implements AutoCloseable {

        final X25519PrivateKeyHandle x25519;
        final MLKem768PrivateKeyHandle mlkem768;

        private HybridPair(
                X25519PrivateKeyHandle x25519,
                MLKem768PrivateKeyHandle mlkem768
        ) {
            this.x25519 = x25519;
            this.mlkem768 = mlkem768;
        }

        PublicHybridRecipientKeys publicKeys() {
            byte[] x25519Public = x25519.publicKey();
            byte[] mlkemPublic = mlkem768.publicKey();
            try {
                return new PublicHybridRecipientKeys(x25519Public, mlkemPublic);
            } finally {
                clear(x25519Public);
                clear(mlkemPublic);
            }
        }

        PublicHybridRecipientPrivateKeys privateKeys() {
            return new PublicHybridRecipientPrivateKeys(x25519, mlkem768);
        }

        @Override
        public void close() {
            mlkem768.close();
            x25519.close();
        }
    }
}
