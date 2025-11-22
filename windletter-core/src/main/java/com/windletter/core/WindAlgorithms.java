package com.windletter.core;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

/**
 * Algorithm identifiers and whitelists enforced by the v1 spec.
 * v1 规范要求的算法标识与白名单。
 */
public final class WindAlgorithms {
    public static final String ENC_A256GCM = "A256GCM";
    public static final String ALG_ECDH_ES_A256KW = "ECDH-ES+A256KW";
    public static final String ALG_ML_KEM_768 = "ML-KEM-768";
    public static final String JWS_ALG_EDDSA = "EdDSA";
    public static final String TYP_JWE = "wind+jwe";
    public static final String TYP_JWS = "wind+jws";

    private static final Set<String> ALLOWED_ENC = Set.of(ENC_A256GCM);
    /**
     * Hybrid rule: ML-KEM-768 must be paired with ECDH-ES+A256KW; pure ECDH is allowed.
     * 混合规则：出现 ML-KEM-768 时必须同时有 ECDH-ES+A256KW，单独 ECDH 允许。
     */
    private static final Set<String> ALLOWED_KEM = Set.of(ALG_ECDH_ES_A256KW, ALG_ML_KEM_768);
    private static final Set<String> ALLOWED_JWS = Set.of(JWS_ALG_EDDSA);

    private WindAlgorithms() {
    }

    public static Set<String> allowedEnc() {
        return Collections.unmodifiableSet(ALLOWED_ENC);
    }

    public static Set<String> allowedRecipientAlgs() {
        return Collections.unmodifiableSet(ALLOWED_KEM);
    }

    /**
     * Validate recipient algorithm set under hybrid rule:
     * - Only values from ALLOWED_KEM appear
     * - If ML-KEM-768 is present, ECDH-ES+A256KW must also be present
     * - ECDH-ES+A256KW alone is allowed
     * 按混合规则校验收件人算法集合：
     * - 仅允许白名单算法
     * - 出现 ML-KEM-768 时必须包含 ECDH-ES+A256KW
     * - 仅 ECDH-ES+A256KW 可单独使用
     */
    public static boolean isRecipientAlgorithmSetValid(Collection<String> algs) {
        if (algs == null || algs.isEmpty()) {
            return false;
        }
        for (String alg : algs) {
            if (!ALLOWED_KEM.contains(alg)) {
                return false;
            }
        }
        boolean hasEcdh = algs.contains(ALG_ECDH_ES_A256KW);
        boolean hasMlKem = algs.contains(ALG_ML_KEM_768);
        if (hasMlKem && !hasEcdh) {
            return false;
        }
        return true;
    }

    public static Set<String> allowedJwsAlgs() {
        return Collections.unmodifiableSet(ALLOWED_JWS);
    }
}
