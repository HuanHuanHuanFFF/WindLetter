package com.windletter.api;

import com.windletter.armor.ArmorJsonEnvelope;
import com.windletter.armor.TextArmorCodec;
import com.windletter.core.WindAlgorithms;
import com.windletter.core.encoding.Base64Url;
import com.windletter.crypto.aead.AeadCipher;
import com.windletter.crypto.kem.MlKem768;
import com.windletter.crypto.kem.X25519KeyAgreement;
import com.windletter.crypto.sign.Ed25519Signer;
import com.windletter.protocol.jwe.Recipient;
import com.windletter.protocol.jwe.WindJwe;
import com.windletter.protocol.jws.JwsProtectedHeader;
import com.windletter.protocol.jws.WindJws;
import com.windletter.protocol.payload.WindPayload;
import com.windletter.protocol.service.JweService;
import com.windletter.protocol.service.JwsBindingService;
import com.windletter.protocol.util.JsonUtil;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * High-level decrypt-and-verify entry.
 * 高层解密+验签入口。
 */
public class WindLetterReceiver {

    private final JweService jweService;
    private final JwsBindingService jwsBindingService;
    private final AeadCipher aeadCipher;
    private final Ed25519Signer verifier;

    public WindLetterReceiver(JweService jweService, JwsBindingService jwsBindingService, AeadCipher aeadCipher, Ed25519Signer verifier) {
        this.jweService = jweService;
        this.jwsBindingService = jwsBindingService;
        this.aeadCipher = aeadCipher;
        this.verifier = verifier;
    }

    public DecryptResult decryptAndVerify(String jweOrArmorText, RecipientKeyStore keyStore) {
        return decryptAndVerify(jweOrArmorText, keyStore, Map.of());
    }

    public DecryptResult decryptAndVerify(String jweOrArmorText, RecipientKeyStore keyStore, Map<String, byte[]> senderPublicKeys) {
        if (jweOrArmorText == null) {
            throw new IllegalArgumentException("input is null");
        }
        WindJwe jwe = parseJweOrArmor(jweOrArmorText);
        if (!jweService.validateEnc(WindAlgorithms.ENC_A256GCM)) {
            throw new IllegalArgumentException("Unsupported enc");
        }
        String aadExpected = jweService.computeAadBase64(jwe.getRecipients());
        if (!aadExpected.equals(jwe.getAad())) {
            throw new IllegalArgumentException("AAD mismatch");
        }
        byte[] aadBytes = jweService.buildAadBytes(jwe.getProtectedB64(), jwe.getAad());
        byte[] cek = deriveCek(jwe.getRecipients(), keyStore);
        byte[] iv = Base64Url.decode(jwe.getIv());
        byte[] ciphertext = Base64Url.decode(jwe.getCiphertext());
        byte[] tag = Base64Url.decode(jwe.getTag());
        byte[] jwsBytes = aeadCipher.decrypt(cek, iv, aadBytes, ciphertext, tag);
        WindJws inner = JsonUtil.fromJson(new String(jwsBytes, StandardCharsets.UTF_8), WindJws.class);
        JwsProtectedHeader protectedHeader = JsonUtil.fromJson(new String(Base64Url.decode(inner.getProtectedB64()), StandardCharsets.UTF_8), JwsProtectedHeader.class);
        boolean bindingsOk = jwsBindingService.verifyBindings(inner, new String(Base64Url.decode(jwe.getProtectedB64()), StandardCharsets.UTF_8), jwe.getRecipients(), protectedHeader);
        boolean signatureOk = false;
        if (protectedHeader.getKid() != null && senderPublicKeys.containsKey(protectedHeader.getKid())) {
            byte[] msg = (inner.getProtectedB64() + "." + inner.getPayloadB64()).getBytes(StandardCharsets.US_ASCII);
            signatureOk = verifier.verify(senderPublicKeys.get(protectedHeader.getKid()), msg, Base64Url.decode(inner.getSignatureB64()));
        }
        WindPayload payload = JsonUtil.fromJson(new String(Base64Url.decode(inner.getPayloadB64()), StandardCharsets.UTF_8), WindPayload.class);
        return new DecryptResult(payload, protectedHeader.getKid(), signatureOk && bindingsOk, "A256GCM");
    }

    private WindJwe parseJweOrArmor(String text) {
        try {
            return JsonUtil.fromJson(text, WindJwe.class);
        } catch (Exception e) {
            // try armor json
            try {
                ArmorJsonEnvelope env = JsonUtil.fromJson(text, ArmorJsonEnvelope.class);
                return JsonUtil.fromJson(new String(Base64Url.decode(env.getData()), StandardCharsets.UTF_8), WindJwe.class);
            } catch (Exception ignored) {
                // try text armor
                TextArmorCodec codec = new TextArmorCodec();
                String data = codec.fromArmor(text).getData();
                return JsonUtil.fromJson(new String(Base64Url.decode(data), StandardCharsets.UTF_8), WindJwe.class);
            }
        }
    }

    private byte[] deriveCek(List<Recipient> recipients, RecipientKeyStore keyStore) {
        for (Recipient r : recipients) {
            if (r.getHeader() == null || r.getHeader().getAlg() == null) {
                continue;
            }
            if (WindAlgorithms.ALG_ECDH_ES_A256KW.equals(r.getHeader().getAlg()) && r.getHeader().getKid() != null) {
                var keyPair = keyStore.findEccKeyByKid(r.getHeader().getKid());
                if (keyPair == null) {
                    continue;
                }
                byte[] epkPub = Base64Url.decode(r.getHeader().getEpk().getX());
                X25519KeyAgreement agree = new X25519KeyAgreement();
                byte[] shared = agree.deriveSharedSecret(keyPair.getPrivateKey(), epkPub);
                byte[] kek = new com.windletter.crypto.hash.WindHash().hkdfSha256(shared, new byte[32], "A256KW".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 32);
                AESWrapEngine unwrap = new AESWrapEngine();
                unwrap.init(false, new KeyParameter(kek));
                byte[] wrapped = Base64Url.decode(r.getEncryptedKey());
                try {
                    return unwrap.unwrap(wrapped, 0, wrapped.length);
                } catch (InvalidCipherTextException e) {
                    throw new IllegalArgumentException("Failed to unwrap CEK", e);
                }
            } else if (WindAlgorithms.ALG_ML_KEM_768.equals(r.getHeader().getAlg()) && r.getHeader().getKid() != null) {
                var keyPair = keyStore.findPqcKeyByKid(r.getHeader().getKid());
                if (keyPair == null) {
                    continue;
                }
                byte[] combined = Base64Url.decode(r.getEncryptedKey());
                // Assume encapsulated || wrappedCek
                int encapsulatedLen = combined.length / 2; // heuristic; Kyber768 ciphertext size is fixed 1088 bytes
                byte[] encap = java.util.Arrays.copyOfRange(combined, 0, encapsulatedLen);
                byte[] wrappedCek = java.util.Arrays.copyOfRange(combined, encapsulatedLen, combined.length);
                byte[] shared = new MlKem768().decapsulate(keyPair.getPrivateKey(), encap);
                byte[] kek = new com.windletter.crypto.hash.WindHash().hkdfSha256(shared, new byte[32], "A256KW".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 32);
                AESWrapEngine unwrap = new AESWrapEngine();
                unwrap.init(false, new KeyParameter(kek));
                try {
                    return unwrap.unwrap(wrappedCek, 0, wrappedCek.length);
                } catch (InvalidCipherTextException e) {
                    throw new IllegalArgumentException("Failed to unwrap CEK (PQC)", e);
                }
            }
        }
        throw new IllegalArgumentException("No matching recipient key");
    }
}
