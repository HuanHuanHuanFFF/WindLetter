package com.windletter.protocol.binding;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.RecipientEntry;
import java.util.Base64;
import java.util.List;

/**
 * AAD service implementing Base64URL(JCS(recipients)).
 */
public final class JcsAadService implements AadService {

    private final JcsCanonicalizer canonicalizer;

    /**
     * Create service with RFC8785 canonicalizer.
     */
    public JcsAadService() {
        this(new Rfc8785JcsCanonicalizer());
    }

    /**
     * Create service with caller-provided canonicalizer.
     */
    public JcsAadService(JcsCanonicalizer canonicalizer) {
        if (canonicalizer == null) {
            throw new IllegalArgumentException("canonicalizer must not be null");
        }
        this.canonicalizer = canonicalizer;
    }

    /**
     * Compute aad from typed recipient list.
     */
    @Override
    public String computeAadBase64Url(List<RecipientEntry> recipients) {
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        byte[] canonicalized = canonicalizer.canonicalize(recipients);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(canonicalized);
    }

    /**
     * Compute aad from raw recipients JSON node.
     */
    @Override
    public String computeAadBase64Url(JsonNode recipientsNode) {
        if (recipientsNode == null) {
            throw new IllegalArgumentException("recipientsNode must not be null");
        }
        byte[] canonicalized = canonicalizer.canonicalize(recipientsNode);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(canonicalized);
    }
}
