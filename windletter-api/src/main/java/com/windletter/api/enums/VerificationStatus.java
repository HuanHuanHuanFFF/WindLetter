package com.windletter.api.enums;

/**
 * 验签结果状态。
 */
public enum VerificationStatus {
    /** 已签名且验证通过。 */
    SIGNED_VALID,
    /** 明确为不签名消息。 */
    UNSIGNED,
    /** 当前流程不适用验签。 */
    NOT_APPLICABLE,
    /** 验签失败。 */
    FAILED
}
