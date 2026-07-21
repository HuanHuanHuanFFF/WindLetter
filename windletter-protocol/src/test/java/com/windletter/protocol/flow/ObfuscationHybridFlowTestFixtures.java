package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
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
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientBuilder;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientKeys;
import com.windletter.protocol.routing.ObfuscationHybridCekRecovery;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

final class ObfuscationHybridFlowTestFixtures implements AutoCloseable {

    static final String IDENTITY_ID = "obfuscation-hybrid-sender-identity";

    final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
    final BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
    final BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
    final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
    final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
    final BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();
    final ObfuscationHybridKeyDeriver keyDeriver =
            new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);

    final Ed25519PrivateKeyHandle senderSigning = ed25519.generatePrivateKey();
    final Ed25519PrivateKeyHandle unrelatedSigning = ed25519.generatePrivateKey();

    final HybridPair first = newPair();
    final HybridPair middle = newPair();
    final HybridPair last = newPair();
    final HybridPair unrelated = newPair();

    final String signingKid;
    final String unrelatedSigningKid;

    ObfuscationHybridFlowTestFixtures() {
        signingKid = signingKid(senderSigning);
        unrelatedSigningKid = signingKid(unrelatedSigning);
    }

    ProtocolPayload binaryPayload() {
        return new ProtocolPayload(
                ProtocolFlowTestFixtures.CONTENT_TYPE,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD.length
        );
    }

    ProtocolPayload textPayload() {
        byte[] text = "WindLetter 文本".getBytes(StandardCharsets.UTF_8);
        try {
            return new ProtocolPayload(
                    "text/plain; charset=utf-8", text, text.length
            );
        } finally {
            clear(text);
        }
    }

    ProtocolPayload emptyPayload() {
        return new ProtocolPayload("application/octet-stream", new byte[0], 0);
    }

    List<HybridPair> recipients() {
        return List.of(first, middle, last);
    }

    ObfuscationHybridRecipientBuilder builder() {
        return new ObfuscationHybridRecipientBuilder(
                x25519, mlkem768, hkdf, keyWrap
        );
    }

    ObfuscationHybridCekRecovery recovery() {
        return new ObfuscationHybridCekRecovery(keyDeriver, keyWrap);
    }

    ObfuscationHybridUnsignedSender sender() {
        return new ObfuscationHybridUnsignedSender(builder(), gcm);
    }

    ObfuscationHybridUnsignedReceiver receiver() {
        return new ObfuscationHybridUnsignedReceiver(recovery(), gcm);
    }

    ObfuscationHybridSignedSender signedSender() {
        return new ObfuscationHybridSignedSender(builder(), gcm, ed25519);
    }

    ObfuscationHybridSignedReceiver signedReceiver() {
        return new ObfuscationHybridSignedReceiver(recovery(), gcm, ed25519);
    }

    String send(ProtocolPayload payload) {
        return sender().send(new ObfuscationHybridUnsignedSender.Request(
                payload,
                ProtocolFlowTestFixtures.MESSAGE_ID,
                ProtocolFlowTestFixtures.TIMESTAMP,
                recipients().stream().map(HybridPair::publicKeys).toList()
        )).wireJson();
    }

    String sendSigned(ProtocolPayload payload) {
        return signedSender().send(new ObfuscationHybridSignedSender.Request(
                payload,
                ProtocolFlowTestFixtures.MESSAGE_ID,
                ProtocolFlowTestFixtures.TIMESTAMP,
                senderSigning,
                recipients().stream().map(HybridPair::publicKeys).toList()
        )).wireJson();
    }

    ObfuscationHybridUnsignedReceiver.Request request(
            String wire,
            List<ObfuscationHybridRecipientPrivateKeys> privateKeys
    ) {
        return new ObfuscationHybridUnsignedReceiver.Request(wire, privateKeys);
    }

    ObfuscationHybridSignedReceiver.Request signedRequest(
            String wire,
            Ed25519VerificationKeyResolver resolver,
            List<ObfuscationHybridRecipientPrivateKeys> privateKeys
    ) {
        return new ObfuscationHybridSignedReceiver.Request(
                wire, resolver, privateKeys
        );
    }

    Ed25519VerificationKeyResolver trustedSigningResolver() {
        return requestedKid -> signingKid.equals(requestedKid)
                ? java.util.Optional.of(trustedSigningKey())
                : java.util.Optional.empty();
    }

    TrustedEd25519Key trustedSigningKey() {
        byte[] publicKey = senderSigning.publicKey();
        try {
            return new TrustedEd25519Key(IDENTITY_ID, signingKid, publicKey);
        } finally {
            clear(publicKey);
        }
    }

    String authenticatedWrongBinding(String originalWire, HybridPair recipient) {
        byte[] inner = null;
        byte[] protectedHash = new byte[32];
        byte[] recipientsHash = new byte[32];
        try {
            inner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    ProtocolFlowTestFixtures.MESSAGE_ID,
                    ProtocolFlowTestFixtures.TIMESTAMP,
                    binaryPayload(),
                    new OuterBinding.Hashes(protectedHash, recipientsHash)
            ));
            return reencrypt(originalWire, recipient, inner);
        } finally {
            clear(inner);
            clear(protectedHash);
            clear(recipientsHash);
        }
    }

    String authenticatedSignedWrongBinding(
            String originalWire,
            HybridPair recipient
    ) {
        byte[] protectedHash = new byte[32];
        byte[] recipientsHash = new byte[32];
        byte[] inner = null;
        try {
            inner = signedInner(
                    new OuterBinding.Hashes(protectedHash, recipientsHash),
                    senderSigning,
                    signingKid
            );
            return reencrypt(originalWire, recipient, inner);
        } finally {
            clear(protectedHash);
            clear(recipientsHash);
            clear(inner);
        }
    }

    String authenticatedFlippedSignature(
            String originalWire,
            HybridPair recipient
    ) {
        byte[] inner = validSignedInner(originalWire, senderSigning, signingKid);
        byte[] signature = null;
        byte[] malicious = null;
        try {
            ObjectNode root = ProtocolFlowTestFixtures.parseObject(
                    new String(inner, StandardCharsets.UTF_8)
            );
            signature = Base64Url.decodeCanonical(
                    root.get("signature").textValue(), "test.inner.signature"
            );
            signature[0] ^= 1;
            root.put("signature", Base64Url.encode(signature));
            malicious = JcsCanonicalizer.canonicalize(root);
            return reencrypt(originalWire, recipient, malicious);
        } finally {
            clear(inner);
            clear(signature);
            clear(malicious);
        }
    }

    String authenticatedUnknownSigner(
            String originalWire,
            HybridPair recipient
    ) {
        byte[] inner = validSignedInner(
                originalWire, unrelatedSigning, unrelatedSigningKid
        );
        try {
            return reencrypt(originalWire, recipient, inner);
        } finally {
            clear(inner);
        }
    }

    String authenticatedWrongKeySignature(
            String originalWire,
            HybridPair recipient
    ) {
        byte[] inner = validSignedInner(
                originalWire, senderSigning, unrelatedSigningKid
        );
        try {
            return reencrypt(originalWire, recipient, inner);
        } finally {
            clear(inner);
        }
    }

    String authenticatedNonCanonicalSignedWire(
            String originalWire,
            HybridPair recipient
    ) {
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
            String protectedJson = "{\"wind_id\":\""
                    + ProtocolFlowTestFixtures.MESSAGE_ID
                    + "\", \"ts\":" + ProtocolFlowTestFixtures.TIMESTAMP
                    + ", \"typ\":\"wind+jws\", \"kid\":\"" + signingKid
                    + "\", \"jwe_recipients_hash\":\""
                    + Base64Url.encode(recipientsHash)
                    + "\", \"jwe_protected_hash\":\""
                    + Base64Url.encode(protectedHash)
                    + "\", \"alg\":\"EdDSA\"}";
            String payloadJson = "{\"meta\":{\"original_size\":"
                    + payloadData.length
                    + ",\"content_type\":\""
                    + ProtocolFlowTestFixtures.CONTENT_TYPE
                    + "\"},\"body\":{\"data\":\""
                    + Base64Url.encode(payloadData) + "\"}}";
            String protectedValue = Base64Url.encode(
                    protectedJson.getBytes(StandardCharsets.UTF_8)
            );
            String payloadValue = Base64Url.encode(
                    payloadJson.getBytes(StandardCharsets.UTF_8)
            );
            signingInput = (protectedValue + "." + payloadValue)
                    .getBytes(StandardCharsets.US_ASCII);
            signature = ed25519.sign(senderSigning, signingInput);
            ObjectNode root = ProtocolFlowTestFixtures.parseObject("{}");
            root.put("signature", Base64Url.encode(signature));
            root.put("payload", payloadValue);
            root.put("protected", protectedValue);
            inner = JcsCanonicalizer.canonicalize(root);
            return reencrypt(originalWire, recipient, inner);
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
            Ed25519PrivateKeyHandle signingKey,
            String kid
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
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
            String originalWire,
            HybridPair recipient,
            byte[] inner
    ) {
        WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
        byte[] cek = null;
        byte[] aad = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] tag = null;
        try {
            cek = recovery().recover(
                    (Epk) parsed.protectedHeader().senderInfo(),
                    parsed.recipients(),
                    List.of(recipient.privateKeys())
            );
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
            clear(cek);
            clear(aad);
            clear(iv);
            clear(ciphertext);
            clear(tag);
        }
    }

    private static String signingKid(Ed25519PrivateKeyHandle handle) {
        byte[] publicKey = handle.publicKey();
        try {
            return Ed25519KeyId.derive(publicKey);
        } finally {
            clear(publicKey);
        }
    }

    private HybridPair newPair() {
        return new HybridPair(
                x25519.generatePrivateKey(), mlkem768.generatePrivateKey()
        );
    }

    @Override
    public void close() {
        unrelated.close();
        last.close();
        middle.close();
        first.close();
        unrelatedSigning.close();
        senderSigning.close();
    }

    static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
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

        ObfuscationHybridRecipientKeys publicKeys() {
            byte[] x25519Public = x25519.publicKey();
            byte[] mlkem768Public = mlkem768.publicKey();
            try {
                return new ObfuscationHybridRecipientKeys(
                        x25519Public, mlkem768Public
                );
            } finally {
                clear(x25519Public);
                clear(mlkem768Public);
            }
        }

        ObfuscationHybridRecipientPrivateKeys privateKeys() {
            return new ObfuscationHybridRecipientPrivateKeys(x25519, mlkem768);
        }

        @Override
        public void close() {
            mlkem768.close();
            x25519.close();
        }
    }
}
