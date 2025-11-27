package com.windletter.api;

import com.windletter.armor.ArmorEncoding;
import com.windletter.armor.ArmorJsonEnvelope;
import com.windletter.armor.JsonArmorCodec;
import com.windletter.armor.TextArmorCodec;
import com.windletter.core.WindAlgorithms;
import com.windletter.core.encoding.Base64Url;
import com.windletter.crypto.WindRandom;
import com.windletter.crypto.aead.AeadCipher;
import com.windletter.crypto.aead.AeadResult;
import com.windletter.crypto.hash.WindHash;
import com.windletter.crypto.kem.MlKem768;
import com.windletter.crypto.kem.X25519KeyAgreement;
import com.windletter.crypto.sign.Ed25519Signer;
import com.windletter.protocol.RecipientPublicInfo;
import com.windletter.protocol.WindMode;
import com.windletter.protocol.jwe.JweProtectedHeader;
import com.windletter.protocol.jwe.Recipient;
import com.windletter.protocol.jwe.RecipientHeader;
import com.windletter.protocol.jwe.WindJwe;
import com.windletter.protocol.jws.JwsProtectedHeader;
import com.windletter.protocol.jws.WindJws;
import com.windletter.protocol.payload.WindPayload;
import com.windletter.protocol.service.JweService;
import com.windletter.protocol.service.JwsBindingService;
import com.windletter.protocol.util.JsonUtil;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

/**
 * High-level encrypt-and-sign entry.
 * 高层加密+签名入口。
 */
public class WindLetterSender {

    private final JweService jweService;
    private final JwsBindingService jwsBindingService;
    private final AeadCipher aeadCipher;
    private final WindHash hash;
    private final Ed25519Signer signer;

    public WindLetterSender(JweService jweService, JwsBindingService jwsBindingService, AeadCipher aeadCipher, WindHash hash, Ed25519Signer signer) {
        this.jweService = jweService;
        this.jwsBindingService = jwsBindingService;
        this.aeadCipher = aeadCipher;
        this.hash = hash;
        this.signer = signer;
    }

    public EncryptedMessage encryptAndSign(WindPayload payload,
                                           WindIdentity sender,
                                           List<RecipientPublicInfo> recipients,
                                           WindMode mode) {
        if (sender == null || sender.getSignKey() == null) {
            throw new IllegalArgumentException("Sender identity/sign key required");
        }
        if (recipients == null || recipients.isEmpty()) {
            throw new IllegalArgumentException("Recipients required");
        }

        byte[] cek = WindRandom.randomBytes(com.windletter.core.WindConstants.CEK_SIZE_BYTES);

        JweProtectedHeader protectedHeader = new JweProtectedHeader(
                WindAlgorithms.TYP_JWE,
                WindAlgorithms.TYP_JWS,
                com.windletter.core.WindConstants.DEFAULT_VERSION,
                mode,
                WindAlgorithms.ENC_A256GCM,
                null
        );
        String protectedJson = JsonUtil.toJson(protectedHeader);
        String protectedB64 = JsonUtil.canonicalize(protectedJson);
        protectedB64 = com.windletter.core.encoding.Base64Url.encode(protectedB64.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        List<Recipient> recipientEntries = recipients.stream().map(r -> buildRecipient(r, cek)).collect(Collectors.toList());

        String aadB64 = jweService.computeAadBase64(recipientEntries);
        byte[] aadBytes = jweService.buildAadBytes(protectedB64, aadB64);

        WindJws innerJws = buildJws(payload, protectedJson, recipientEntries, sender);

        byte[] jwsBytes = JsonUtil.toJson(innerJws).getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] iv = hash.hkdfSha256(cek, new byte[32], com.windletter.core.WindConstants.WIND_ID_INFO.getBytes(java.nio.charset.StandardCharsets.US_ASCII), com.windletter.core.WindConstants.IV_SIZE_BYTES);
        AeadResult enc = aeadCipher.encrypt(cek, iv, aadBytes, jwsBytes);

        WindJwe jwe = new WindJwe(protectedB64, aadB64, recipientEntries,
                com.windletter.core.encoding.Base64Url.encode(iv),
                com.windletter.core.encoding.Base64Url.encode(enc.getCiphertext()),
                com.windletter.core.encoding.Base64Url.encode(enc.getTag()));

        String jweJson = JsonUtil.toJson(jwe);
        String armorJson = new JsonArmorCodec().toArmor(new ArmorJsonEnvelope("wind-letter", ArmorEncoding.BASE64URL.jsonValue(), "1", Base64Url.encode(jweJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)), null));
        String textArmor = new TextArmorCodec().toArmor(new com.windletter.armor.TextArmorEnvelope(ArmorEncoding.BASE64URL, "1", Base64Url.encode(jweJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)), null));
        return new EncryptedMessage(jwe, jweJson, armorJson + "\n" + textArmor);
    }

    private Recipient buildRecipient(RecipientPublicInfo info, byte[] cek) {
        if (WindAlgorithms.ALG_ECDH_ES_A256KW.equals(info.getAlg())) {
            X25519PrivateKeyParameters epkPriv = new X25519PrivateKeyParameters(new SecureRandom());
            byte[] epkPub = epkPriv.generatePublicKey().getEncoded();
            byte[] shared = new X25519KeyAgreement().deriveSharedSecret(epkPriv.getEncoded(), info.getPublicKeyBytes());
            byte[] kek = hash.hkdfSha256(shared, new byte[32], "A256KW".getBytes(StandardCharsets.US_ASCII), 32);
            AESWrapEngine wrapEngine = new AESWrapEngine();
            wrapEngine.init(true, new KeyParameter(kek));
            byte[] wrapped = wrapEngine.wrap(cek, 0, cek.length);
            RecipientHeader header = new RecipientHeader(info.getKid(), null, info.getAlg(),
                    new com.windletter.protocol.jwe.Epk("OKP", "X25519", com.windletter.core.encoding.Base64Url.encode(epkPub)));
            return new Recipient(header, com.windletter.core.encoding.Base64Url.encode(wrapped));
        } else if (WindAlgorithms.ALG_ML_KEM_768.equals(info.getAlg())) {
            MlKem768 kem = new MlKem768();
            var encap = kem.encapsulate(info.getPublicKeyBytes());
            // Use HKDF on shared secret for CEK wrapping (simple XOR with HKDF-derived key for now)
            byte[] kek = hash.hkdfSha256(encap.getSharedSecret(), new byte[32], "A256KW".getBytes(StandardCharsets.US_ASCII), 32);
            AESWrapEngine wrapEngine = new AESWrapEngine();
            wrapEngine.init(true, new KeyParameter(kek));
            byte[] wrappedCek = wrapEngine.wrap(cek, 0, cek.length);
            RecipientHeader header = new RecipientHeader(info.getKid(), null, info.getAlg(), null);
            // Store encapsulated key concatenated with wrapped CEK: encap || wrap(cek)
            byte[] combined = new byte[encap.getEncapsulated().length + wrappedCek.length];
            System.arraycopy(encap.getEncapsulated(), 0, combined, 0, encap.getEncapsulated().length);
            System.arraycopy(wrappedCek, 0, combined, encap.getEncapsulated().length, wrappedCek.length);
            return new Recipient(header, Base64Url.encode(combined));
        } else {
            throw new IllegalArgumentException("Unsupported alg for sender: " + info.getAlg());
        }
    }

    private WindJws buildJws(WindPayload payload, String outerProtectedJson, List<Recipient> recipients, WindIdentity sender) {
        String pht = jwsBindingService.computePht(outerProtectedJson);
        String rch = jwsBindingService.computeRch(recipients);
        JwsProtectedHeader protectedHeader = new JwsProtectedHeader(
                WindAlgorithms.TYP_JWS,
                WindAlgorithms.JWS_ALG_EDDSA,
                sender.getSignKey().getKid(),
                System.currentTimeMillis() / 1000,
                pht,
                rch
        );
        String protectedJson = JsonUtil.toJson(protectedHeader);
        String protectedCanon = JsonUtil.canonicalize(protectedJson);
        String protectedB64 = com.windletter.core.encoding.Base64Url.encode(protectedCanon.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payloadJson = JsonUtil.toJson(payload);
        String payloadB64 = com.windletter.core.encoding.Base64Url.encode(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String signingInput = protectedB64 + "." + payloadB64;
        byte[] signature = signer.sign(sender.getSignKey().getPrivateKey(), signingInput.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String signatureB64 = com.windletter.core.encoding.Base64Url.encode(signature);
        return new WindJws(protectedB64, payloadB64, signatureB64);
    }
}
