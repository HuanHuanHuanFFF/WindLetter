package com.windletter.protocol.service;

import com.windletter.core.encoding.Base64Url;
import com.windletter.core.util.Bytes;
import com.windletter.crypto.hash.WindHash;
import com.windletter.protocol.jcs.JsonCanonicalizer;
import com.windletter.protocol.jws.JwsProtectedHeader;
import com.windletter.protocol.jws.WindJws;
import com.windletter.protocol.jwe.Recipient;
import com.windletter.protocol.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * JWS binding helpers for pht/rch computation and verification.
 * JWS 绑定（pht/rch）计算与校验工具。
 */
public class JwsBindingService {
    private final JsonCanonicalizer canonicalizer;
    private final WindHash hash;

    public JwsBindingService(JsonCanonicalizer canonicalizer, WindHash hash) {
        this.canonicalizer = canonicalizer;
        this.hash = hash;
    }

    public String computePht(String protectedJson) {
        String canon = canonicalizer.canonicalize(protectedJson);
        byte[] digest = hash.sha256(canon.getBytes(StandardCharsets.UTF_8));
        return Base64Url.encode(digest);
    }

    public String computeRch(List<Recipient> recipients) {
        String canon = canonicalizer.canonicalize(JsonUtil.toJson(recipients));
        byte[] digest = hash.sha256(canon.getBytes(StandardCharsets.UTF_8));
        return Base64Url.encode(digest);
    }

    public boolean verifyBindings(WindJws jws, String outerProtectedJson, List<Recipient> recipients, JwsProtectedHeader header) {
        String expectedPht = computePht(outerProtectedJson);
        String expectedRch = computeRch(recipients);
        boolean phtOk = Bytes.constantTimeEquals(Base64Url.decode(header.getPht()), Base64Url.decode(expectedPht));
        boolean rchOk = Bytes.constantTimeEquals(Base64Url.decode(header.getRch()), Base64Url.decode(expectedRch));
        return phtOk && rchOk;
    }
}
