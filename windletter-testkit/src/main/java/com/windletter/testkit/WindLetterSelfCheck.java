package com.windletter.testkit;

import com.windletter.api.DecryptResult;
import com.windletter.api.EncryptedMessage;
import com.windletter.api.IdentityGenerator;
import com.windletter.api.RecipientKeyStore;
import com.windletter.api.WindIdentity;
import com.windletter.api.WindLetterReceiver;
import com.windletter.api.WindLetterSender;
import com.windletter.core.WindAlgorithms;
import com.windletter.crypto.aead.AesGcmCipher;
import com.windletter.crypto.hash.WindHash;
import com.windletter.crypto.keys.EccKeyPair;
import com.windletter.crypto.keys.KeyGenerator;
import com.windletter.crypto.keys.PqcKemKeyPair;
import com.windletter.crypto.sign.Ed25519Signer;
import com.windletter.protocol.RecipientPublicInfo;
import com.windletter.protocol.WindMode;
import com.windletter.protocol.jcs.DefaultJsonCanonicalizer;
import com.windletter.protocol.payload.WindPayload;
import com.windletter.protocol.service.JweService;
import com.windletter.protocol.service.JwsBindingService;

import java.util.List;
import java.util.Map;

/**
 * Entry point for automated self-check routines.
 * 自动自检流程的入口。
 */
public class WindLetterSelfCheck {

    public static SelfCheckReport run() {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            IdentityGenerator identityGenerator = new IdentityGenerator(keyGenerator, true);
            WindIdentity sender = identityGenerator.generate();
            WindIdentity receiver = identityGenerator.generate();

            JweService jweService = new JweService(new DefaultJsonCanonicalizer());
            JwsBindingService jwsBindingService = new JwsBindingService(new DefaultJsonCanonicalizer(), new WindHash());
            WindLetterSender senderApi = new WindLetterSender(
                    jweService,
                    jwsBindingService,
                    new AesGcmCipher(),
                    new WindHash(),
                    new Ed25519Signer()
            );
            WindLetterReceiver receiverApi = new WindLetterReceiver(
                    jweService,
                    jwsBindingService,
                    new AesGcmCipher(),
                    new Ed25519Signer()
            );

            WindPayload payload = new WindPayload(
                    new WindPayload.Meta("text/plain; charset=utf-8", 17L),
                    new WindPayload.Body("text", "self-check payload")
            );

            List<RecipientPublicInfo> recipients = List.of(
                    new RecipientPublicInfo(receiver.getKemEccKey().getKid(), WindAlgorithms.ALG_ECDH_ES_A256KW, receiver.getKemEccKey().getPublicKey()),
                    new RecipientPublicInfo(receiver.getKemPqcKey().getKid(), WindAlgorithms.ALG_ML_KEM_768, receiver.getKemPqcKey().getPublicKey())
            );

            EncryptedMessage encrypted = senderApi.encryptAndSign(payload, sender, recipients, WindMode.PUBLIC);
            DecryptResult decrypted = receiverApi.decryptAndVerify(
                    encrypted.getJweJson(),
                    new RecipientKeyStore() {
                        @Override
                        public EccKeyPair findEccKeyByKid(String kid) {
                            return receiver.getKemEccKey().getKid().equals(kid) ? receiver.getKemEccKey() : null;
                        }

                        @Override
                        public PqcKemKeyPair findPqcKeyByKid(String kid) {
                            return receiver.getKemPqcKey().getKid().equals(kid) ? receiver.getKemPqcKey() : null;
                        }
                    },
                    Map.of(sender.getSignKey().getKid(), sender.getSignKey().getPublicKey())
            );

            boolean payloadOk = "self-check payload".equals(decrypted.getPayload().getBody().getText());
            boolean signatureOk = decrypted.isSignatureValid();
            boolean allPassed = payloadOk && signatureOk;
            String details = allPassed
                    ? "Self-check passed: encrypt/decrypt + binding/signature verification succeeded."
                    : "Self-check failed: payloadOk=" + payloadOk + ", signatureOk=" + signatureOk;
            return new SelfCheckReport(allPassed, details);
        } catch (Exception e) {
            return new SelfCheckReport(false, "Self-check failed with exception: " + e.getMessage());
        }
    }
}
