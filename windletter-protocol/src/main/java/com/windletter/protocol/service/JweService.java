package com.windletter.protocol.service;

import com.windletter.core.WindAlgorithms;
import com.windletter.core.encoding.Base64Url;
import com.windletter.protocol.jcs.JsonCanonicalizer;
import com.windletter.protocol.jwe.Recipient;
import com.windletter.protocol.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * JWE helper for AAD computation and whitelist validation.
 * JWE AAD 计算与白名单校验工具。
 */
public class JweService {
    private final JsonCanonicalizer canonicalizer;

    public JweService(JsonCanonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }

    public String computeAadBase64(List<Recipient> recipients) {
        String canon = canonicalizer.canonicalize(JsonUtil.toJson(recipients));
        return Base64Url.encode(canon.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] buildAadBytes(String protectedB64, String aadB64) {
        String combined = protectedB64 + "." + aadB64;
        return combined.getBytes(StandardCharsets.US_ASCII);
    }

    public boolean validateRecipientAlgorithms(List<Recipient> recipients) {
        Set<String> algs = new HashSet<>();
        for (Recipient r : recipients) {
            if (r.getHeader() == null || r.getHeader().getAlg() == null) {
                return false;
            }
            algs.add(r.getHeader().getAlg());
        }
        return WindAlgorithms.isRecipientAlgorithmSetValid(algs);
    }

    public boolean validateEnc(String enc) {
        return WindAlgorithms.allowedEnc().contains(enc);
    }
}
