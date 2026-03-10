package com.windletter.protocol.binding;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.RecipientEntry;
import java.util.List;

/**
 * AAD computation service for outer wire payload.
 */
public interface AadService {

    /**
     * Compute Base64URL(JCS(recipients)) from typed recipient list.
     */
    String computeAadBase64Url(List<RecipientEntry> recipients);

    /**
     * Compute Base64URL(JCS(recipients)) from raw JSON node.
     */
    String computeAadBase64Url(JsonNode recipientsNode);
}
