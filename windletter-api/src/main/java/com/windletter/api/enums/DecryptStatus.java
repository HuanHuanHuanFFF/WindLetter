package com.windletter.api.enums;

/**
 * 解密总状态。
 */
public enum DecryptStatus {
    /** 成功解密并产出 payload。 */
    SUCCESS,
    /** 消息不属于当前接收方。 */
    NOT_FOR_ME,
    /** 消息结构或认证校验失败。 */
    INVALID_MESSAGE,
    /** 版本或算法不支持。 */
    UNSUPPORTED
}
