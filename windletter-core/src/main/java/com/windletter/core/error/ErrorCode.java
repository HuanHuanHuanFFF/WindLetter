package com.windletter.core.error;

/**
 * 对外稳定错误码。
 * <p>
 * 这里的枚举是 API 层与实现层之间的统一契约，新增时应保持向后兼容。
 */
public enum ErrorCode {
    /** Wire 结构或 JSON 形态不合法。 */
    MALFORMED_WIRE,
    /** 协议版本不支持。 */
    UNSUPPORTED_VERSION,
    /** 算法或算法组合不支持。 */
    UNSUPPORTED_ALGORITHM,
    /** 消息不是发给当前身份。 */
    NOT_FOR_ME,
    /** AAD 复算不一致。 */
    AAD_MISMATCH,
    /** CEK unwrap 失败。 */
    KEY_UNWRAP_FAILED,
    /** GCM 认证失败（含 tag 校验失败）。 */
    GCM_AUTH_FAILED,
    /** 内外层绑定校验失败。 */
    BINDING_FAILED,
    /** 签名校验失败。 */
    SIGNATURE_INVALID,
    /** 字段缺失、冲突或取值非法。 */
    INVALID_FIELD,
    /** 其他未分类内部错误。 */
    INTERNAL_ERROR
}
