package com.windletter.protocol.flow;

import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.ObfuscationHybridKeyDeriver;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientBuilder;
import com.windletter.protocol.recipient.ObfuscationHybridRecipientKeys;
import com.windletter.protocol.routing.ObfuscationHybridCekRecovery;
import com.windletter.protocol.routing.ObfuscationHybridRecipientPrivateKeys;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.WindLetter;

import java.util.Arrays;
import java.util.List;

final class ObfuscationHybridFlowTestFixtures implements AutoCloseable {

    final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
    final BouncyCastleMLKem768Crypto mlkem768 = new BouncyCastleMLKem768Crypto();
    final BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
    final BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
    final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
    final ObfuscationHybridKeyDeriver keyDeriver =
            new ObfuscationHybridKeyDeriver(x25519, mlkem768, hkdf);

    final HybridPair first = newPair();
    final HybridPair middle = newPair();
    final HybridPair last = newPair();
    final HybridPair unrelated = newPair();

    ProtocolPayload binaryPayload() {
        return new ProtocolPayload(
                ProtocolFlowTestFixtures.CONTENT_TYPE,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD,
                ProtocolFlowTestFixtures.BINARY_PAYLOAD.length
        );
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

    String send(ProtocolPayload payload) {
        return sender().send(new ObfuscationHybridUnsignedSender.Request(
                payload,
                ProtocolFlowTestFixtures.MESSAGE_ID,
                ProtocolFlowTestFixtures.TIMESTAMP,
                recipients().stream().map(HybridPair::publicKeys).toList()
        )).wireJson();
    }

    ObfuscationHybridUnsignedReceiver.Request request(
            String wire,
            List<ObfuscationHybridRecipientPrivateKeys> privateKeys
    ) {
        return new ObfuscationHybridUnsignedReceiver.Request(wire, privateKeys);
    }

    String authenticatedWrongBinding(String originalWire, HybridPair recipient) {
        WindLetter parsed = new JacksonOuterWireParser().parse(originalWire);
        byte[] cek = null;
        byte[] aad = null;
        byte[] iv = null;
        byte[] inner = null;
        byte[] ciphertext = null;
        byte[] tag = null;
        byte[] protectedHash = new byte[32];
        byte[] recipientsHash = new byte[32];
        try {
            cek = recovery().recover(
                    (Epk) parsed.protectedHeader().senderInfo(),
                    parsed.recipients(),
                    List.of(recipient.privateKeys())
            );
            inner = new UnsignedInnerCodec().encode(new UnsignedInnerCodec.Message(
                    ProtocolFlowTestFixtures.MESSAGE_ID,
                    ProtocolFlowTestFixtures.TIMESTAMP,
                    binaryPayload(),
                    new OuterBinding.Hashes(protectedHash, recipientsHash)
            ));
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
            clear(inner);
            clear(ciphertext);
            clear(tag);
            clear(protectedHash);
            clear(recipientsHash);
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
