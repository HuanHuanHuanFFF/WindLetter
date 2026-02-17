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
        // Result semantic constraints: success must contain payload, failure must not contain payload.
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
