package com.windletter.api.model;

import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.core.error.ErrorCode;

/**
 * 接收侧返回结果。
 *
 * @param status 解密总状态
 * @param payload 仅在 SUCCESS 时存在
 * @param senderIdentity 验签成功后可选提供
 * @param verificationStatus 验签状态
 * @param errorCode 非成功时可选错误码
 * @param messageId 内层 wind_id（可选）
 * @param timestamp 内层 ts（可选）
 */
public record DecryptResult(
    DecryptStatus status,
    Payload payload,
    SenderIdentity senderIdentity,
    VerificationStatus verificationStatus,
    ErrorCode errorCode,
    String messageId,
    Long timestamp
) {

    public DecryptResult {
        status = ModelChecks.requireNonNull(status, "status");
        verificationStatus = ModelChecks.requireNonNull(verificationStatus, "verificationStatus");
        // 结果语义约束：成功必须带 payload，失败必须不带 payload。
        if (status == DecryptStatus.SUCCESS && payload == null) {
            throw new IllegalArgumentException("payload is required when status is SUCCESS");
        }
        if (status != DecryptStatus.SUCCESS && payload != null) {
            throw new IllegalArgumentException("payload must be null when status is not SUCCESS");
        }
        if (status == DecryptStatus.SUCCESS && errorCode != null) {
            throw new IllegalArgumentException("errorCode must be null when status is SUCCESS");
        }
    }
}
