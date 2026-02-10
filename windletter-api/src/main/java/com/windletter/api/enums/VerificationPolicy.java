package com.windletter.api.enums;

/**
 * 接收侧验签策略。
 */
public enum VerificationPolicy {
    /** 按消息 cty 自动决定是否验签。 */
    AUTO_BY_CTY,
    /** 要求签名且必须验证通过。 */
    REQUIRE_SIGNED_VALID,
    /** 允许无签名消息通过。 */
    ALLOW_UNSIGNED
}
