package com.windletter.testkit;

import com.windletter.api.*;
import com.windletter.core.encoding.Base64Url;
import com.windletter.crypto.aead.AesGcmCipher;
import com.windletter.crypto.hash.WindHash;
import com.windletter.crypto.keys.EccKeyPair;
import com.windletter.crypto.keys.KeyGenerator;
import com.windletter.crypto.keys.PqcKemKeyPair;
import com.windletter.crypto.sign.Ed25519Signer;
import com.windletter.protocol.WindMode;
import com.windletter.protocol.jcs.DefaultJsonCanonicalizer;
import com.windletter.protocol.payload.WindPayload;
import com.windletter.protocol.service.JweService;
import com.windletter.protocol.service.JwsBindingService;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Minimal demo for encrypt/decrypt flow.
 * 简单加解密示例。
 */
public class Demo {
    public static void main(String[] args) {
        // 生成身份（Ed25519 + X25519）
        KeyGenerator keyGen = new KeyGenerator();
        IdentityGenerator idGen = new IdentityGenerator(keyGen, true);
        WindIdentity sender = idGen.generate();
        WindIdentity receiver = idGen.generate();

        System.out.println("Sender Ed25519 pub (b64): " + Base64Url.encode(sender.getSignKey().getPublicKey()));
        System.out.println("Sender Ed25519 priv (b64): " + Base64Url.encode(sender.getSignKey().getPrivateKey()));
        System.out.println("Receiver X25519 pub (b64): " + Base64Url.encode(receiver.getKemEccKey().getPublicKey()));
        System.out.println("Receiver X25519 priv (b64): " + Base64Url.encode(receiver.getKemEccKey().getPrivateKey()));
        if (receiver.getKemPqcKey() != null) {
            System.out.println("Receiver ML-KEM-768 pub (b64): " + Base64Url.encode(receiver.getKemPqcKey().getPublicKey()));
            System.out.println("Receiver ML-KEM-768 priv (b64): " + Base64Url.encode(receiver.getKemPqcKey().getPrivateKey()));
        }

        // 准备依赖
        var canonicalizer = new DefaultJsonCanonicalizer();
        var hash = new WindHash();
        var jweSvc = new JweService(canonicalizer);
        var jwsSvc = new JwsBindingService(canonicalizer, hash);
        var aead = new AesGcmCipher();
        var signer = new Ed25519Signer();
        var senderApi = new WindLetterSender(jweSvc, jwsSvc, aead, hash, signer);
        var receiverApi = new WindLetterReceiver(jweSvc, jwsSvc, aead, signer);

        // 收件人信息（仅 ECDH）
        var rinfoEcc = new com.windletter.protocol.RecipientPublicInfo(
                receiver.getKemEccKey().getKid(),
                com.windletter.core.WindAlgorithms.ALG_ECDH_ES_A256KW,
                receiver.getKemEccKey().getPublicKey()
        );
        var rinfoPqc = new com.windletter.protocol.RecipientPublicInfo(
                receiver.getKemPqcKey().getKid(),
                com.windletter.core.WindAlgorithms.ALG_ML_KEM_768,
                receiver.getKemPqcKey().getPublicKey()
        );

        // 构造 payload
        WindPayload payload = new WindPayload(
                new WindPayload.Meta("text/utf-8", null),
                new WindPayload.Body("text", "Hello, WindLetter!")
        );

        // 加密
        EncryptedMessage em = senderApi.encryptAndSign(payload, sender, List.of(rinfoEcc, rinfoPqc), WindMode.PUBLIC);
        String jweJsonB64 = Base64Url.encode(em.getJweJson().getBytes(StandardCharsets.UTF_8));
        System.out.println("JWE JSON (b64): " + jweJsonB64);

        // 解密（用 JSON base64 输入）
        String jweJson = new String(Base64Url.decode(jweJsonB64), StandardCharsets.UTF_8);
        DecryptResult result = receiverApi.decryptAndVerify(
                jweJson,
                new RecipientKeyStore() {
                    @Override
                    public EccKeyPair findEccKeyByKid(String kid) {
                        return kid.equals(receiver.getKemEccKey().getKid()) ? receiver.getKemEccKey() : null;
                    }

                    @Override
                    public PqcKemKeyPair findPqcKeyByKid(String kid) {
                        return kid.equals(receiver.getKemPqcKey().getKid()) ? receiver.getKemPqcKey() : null;
                    }
                },
                Map.of(sender.getSignKey().getKid(), sender.getSignKey().getPublicKey())
        );
        System.out.println("Decrypted text: " + result.getPayload().getBody().getText());
        System.out.println("Signature ok? " + result.isSignatureValid());

        // 解密（Armor 输入）
        DecryptResult resultArmor = receiverApi.decryptAndVerify(
                em.getArmor(),
                new RecipientKeyStore() {
                    @Override
                    public EccKeyPair findEccKeyByKid(String kid) {
                        return kid.equals(receiver.getKemEccKey().getKid()) ? receiver.getKemEccKey() : null;
                    }

                    @Override
                    public PqcKemKeyPair findPqcKeyByKid(String kid) {
                        return kid.equals(receiver.getKemPqcKey().getKid()) ? receiver.getKemPqcKey() : null;
                    }
                },
                Map.of(sender.getSignKey().getKid(), sender.getSignKey().getPublicKey())
        );
        System.out.println("Armor decrypted text: " + resultArmor.getPayload().getBody().getText());
    }
}
