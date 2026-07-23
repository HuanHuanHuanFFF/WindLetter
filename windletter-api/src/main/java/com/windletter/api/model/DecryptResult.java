package com.windletter.api.model;

import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.core.error.ErrorCode;

/**
 * Receiver-side result.
 *
 * @param status overall decryption status
 * @param payload present only when status is SUCCESS
 * @param senderIdentity optionally provided after successful signature verification
 * @param verificationStatus verification status
 * @param errorCode optional error code when not successful
 * @param messageId inner wind_id (optional)
 * @param timestamp inner ts (optional)
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

    /**
     * Canonical constructor with result-semantic consistency checks.
     *
     * @throws IllegalArgumentException if status/payload/errorCode combinations are inconsistent
     */
    public DecryptResult {
        status = ModelChecks.requireNonNull(status, "status");
        verificationStatus = ModelChecks.requireNonNull(verificationStatus, "verificationStatus");
        if (status == DecryptStatus.SUCCESS) {
            if (payload == null) {
                throw new IllegalArgumentException("payload is required when status is SUCCESS");
            }
            if (errorCode != null) {
                throw new IllegalArgumentException("errorCode must be null when status is SUCCESS");
            }
            if (ModelChecks.isBlank(messageId) || timestamp == null) {
                throw new IllegalArgumentException("messageId and timestamp are required when status is SUCCESS");
            }
            if (verificationStatus == VerificationStatus.UNSIGNED) {
                if (senderIdentity != null) {
                    throw new IllegalArgumentException("senderIdentity must be null for an unsigned success");
                }
            } else if (verificationStatus == VerificationStatus.SIGNED_VALID) {
                if (senderIdentity == null) {
                    throw new IllegalArgumentException("senderIdentity is required for a signed success");
                }
            } else {
                throw new IllegalArgumentException(
                    "success verificationStatus must be UNSIGNED or SIGNED_VALID"
                );
            }
        } else {
            if (payload != null || senderIdentity != null || messageId != null || timestamp != null) {
                throw new IllegalArgumentException(
                    "failure results must not expose payload, identity, messageId or timestamp"
                );
            }
            if (status == DecryptStatus.NOT_FOR_ME) {
                if (verificationStatus != VerificationStatus.NOT_APPLICABLE
                    || errorCode != ErrorCode.NOT_FOR_ME) {
                    throw new IllegalArgumentException("NOT_FOR_ME result shape is inconsistent");
                }
            } else if (status == DecryptStatus.INVALID_MESSAGE) {
                if (verificationStatus != VerificationStatus.FAILED
                    || errorCode != ErrorCode.INVALID_MESSAGE) {
                    throw new IllegalArgumentException("INVALID_MESSAGE result shape is inconsistent");
                }
            } else {
                throw new IllegalArgumentException("UNSUPPORTED is not a public wire result");
            }
        }
    }
}
