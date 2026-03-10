package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.binding.AadService;
import com.windletter.protocol.binding.JcsAadService;
import com.windletter.protocol.wire.DefaultProtectedHeaderCodec;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.ProtectedHeaderCodec;
import com.windletter.protocol.wire.RecipientEntry;
import java.util.List;

/**
 * Default outbound preprocessor for assembling outer wire message.
 */
public final class DefaultOutboundWirePreparer implements OutboundWirePreparer {

    private final ProtectedHeaderCodec protectedHeaderCodec;
    private final AadService aadService;

    /**
     * Create preparer with default protected-header codec and aad service.
     */
    public DefaultOutboundWirePreparer() {
        this(new DefaultProtectedHeaderCodec(), new JcsAadService());
    }

    /**
     * Create preparer with caller-provided dependencies.
     */
    public DefaultOutboundWirePreparer(ProtectedHeaderCodec protectedHeaderCodec, AadService aadService) {
        if (protectedHeaderCodec == null) {
            throw new IllegalArgumentException("protectedHeaderCodec must not be null");
        }
        if (aadService == null) {
            throw new IllegalArgumentException("aadService must not be null");
        }
        this.protectedHeaderCodec = protectedHeaderCodec;
        this.aadService = aadService;
    }

    /**
     * Build outbound wire and always recompute aad from recipients.
     */
    @Override
    public OuterWireMessage prepare(
            ProtectedHeader header,
            List<RecipientEntry> recipients,
            String ivB64,
            String ciphertextB64,
            String tagB64) {
        if (header == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "protected header must not be null");
        }
        if (recipients == null || recipients.isEmpty()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "recipients must be a non-empty array");
        }
        requireNotBlank(ivB64, "iv");
        requireNotBlank(ciphertextB64, "ciphertext");
        requireNotBlank(tagB64, "tag");

        String protectedB64 = protectedHeaderCodec.encode(header);
        String aadB64 = aadService.computeAadBase64Url(recipients);
        return new OuterWireMessage(protectedB64, aadB64, recipients, ivB64, ciphertextB64, tagB64);
    }

    private static void requireNotBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, fieldName + " must not be blank");
        }
    }
}
