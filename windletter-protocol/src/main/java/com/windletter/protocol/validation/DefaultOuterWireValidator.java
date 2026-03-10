package com.windletter.protocol.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.binding.AadService;
import com.windletter.protocol.binding.JcsAadService;
import com.windletter.protocol.wire.DefaultProtectedHeaderCodec;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ParsedOuterWire;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.ProtectedHeaderCodec;
import java.util.regex.Pattern;

/**
 * Default validator for outer wire structure and AAD consistency.
 */
public final class DefaultOuterWireValidator implements OuterWireValidator {

    private static final String VERSION_V1 = "1.0";
    private static final String TYP_WIND_JWE = "wind+jwe";
    private static final String CTY_WIND_JWS = "wind+jws";
    private static final String CTY_WIND_INNER = "wind+inner";
    private static final String MODE_PUBLIC = "public";
    private static final String MODE_OBFUSCATION = "obfuscation";
    private static final String ENC_A256_GCM = "A256GCM";
    private static final String KEY_ALG_X25519 = "X25519";
    private static final String KEY_ALG_HYBRID = "X25519ML-KEM-768";
    private static final Pattern BASE64URL_NO_PADDING = Pattern.compile("^[A-Za-z0-9_-]+$");

    private final AadService aadService;
    private final ProtectedHeaderCodec protectedHeaderCodec;

    /**
     * Create validator with default aad service and protected-header codec.
     */
    public DefaultOuterWireValidator() {
        this(new JcsAadService(), new DefaultProtectedHeaderCodec());
    }

    /**
     * Create validator with caller-provided ObjectMapper and aad service.
     */
    public DefaultOuterWireValidator(ObjectMapper objectMapper, AadService aadService) {
        this(aadService, new DefaultProtectedHeaderCodec(objectMapper));
    }

    /**
     * Create validator with explicit dependencies.
     */
    public DefaultOuterWireValidator(AadService aadService, ProtectedHeaderCodec protectedHeaderCodec) {
        if (aadService == null) {
            throw new IllegalArgumentException("aadService must not be null");
        }
        if (protectedHeaderCodec == null) {
            throw new IllegalArgumentException("protectedHeaderCodec must not be null");
        }
        this.aadService = aadService;
        this.protectedHeaderCodec = protectedHeaderCodec;
    }

    /**
     * Validate required fields, base64url format, and protected header whitelist.
     */
    @Override
    public void validateStructure(OuterWireMessage wire) {
        requireWire(wire);
        requireNotBlank(wire.protectedB64(), "protected");
        requireNotBlank(wire.aadB64(), "aad");
        requireNotBlank(wire.ivB64(), "iv");
        requireNotBlank(wire.ciphertextB64(), "ciphertext");
        requireNotBlank(wire.tagB64(), "tag");
        requireBase64UrlNoPadding(wire.aadB64(), "aad");
        requireBase64UrlNoPadding(wire.ivB64(), "iv");
        requireBase64UrlNoPadding(wire.ciphertextB64(), "ciphertext");
        requireBase64UrlNoPadding(wire.tagB64(), "tag");
        if (wire.recipients() == null || wire.recipients().isEmpty()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "recipients must be a non-empty array");
        }
        ProtectedHeader protectedHeader = decodeProtectedHeader(wire.protectedB64());
        validateProtected(protectedHeader);
    }

    /**
     * Validate protected header literal whitelist for v1.0.
     */
    @Override
    public void validateProtected(ProtectedHeader protectedHeader) {
        if (protectedHeader == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "protected header must not be null");
        }
        if (!VERSION_V1.equals(protectedHeader.ver())) {
            throw new ProtocolException(ErrorCode.UNSUPPORTED_VERSION, "unsupported version: " + protectedHeader.ver());
        }
        if (!TYP_WIND_JWE.equals(protectedHeader.typ())) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "typ must be " + TYP_WIND_JWE);
        }
        if (!CTY_WIND_JWS.equals(protectedHeader.cty()) && !CTY_WIND_INNER.equals(protectedHeader.cty())) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "unsupported cty: " + protectedHeader.cty());
        }
        if (!MODE_PUBLIC.equals(protectedHeader.windMode()) && !MODE_OBFUSCATION.equals(protectedHeader.windMode())) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "unsupported wind_mode: " + protectedHeader.windMode());
        }
        if (!ENC_A256_GCM.equals(protectedHeader.enc())) {
            throw new ProtocolException(ErrorCode.UNSUPPORTED_ALGORITHM, "unsupported enc: " + protectedHeader.enc());
        }
        if (!KEY_ALG_X25519.equals(protectedHeader.keyAlg()) && !KEY_ALG_HYBRID.equals(protectedHeader.keyAlg())) {
            throw new ProtocolException(ErrorCode.UNSUPPORTED_ALGORITHM, "unsupported key_alg: " + protectedHeader.keyAlg());
        }
    }

    /**
     * Recompute aad from raw recipients node and compare with wire aad.
     */
    @Override
    public void validateAadConsistency(ParsedOuterWire parsedWire) {
        if (parsedWire == null || parsedWire.wire() == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "parsedWire must not be null");
        }
        OuterWireMessage wire = parsedWire.wire();
        requireNotBlank(wire.aadB64(), "aad");
        requireBase64UrlNoPadding(wire.aadB64(), "aad");
        if (parsedWire.recipientsNode() == null || !parsedWire.recipientsNode().isArray() || parsedWire.recipientsNode().isEmpty()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "recipients must be a non-empty array");
        }
        String expected = aadService.computeAadBase64Url(parsedWire.recipientsNode());
        if (!expected.equals(wire.aadB64())) {
            throw new ProtocolException(ErrorCode.AAD_MISMATCH, "aad mismatch");
        }
    }

    private ProtectedHeader decodeProtectedHeader(String protectedB64) {
        return protectedHeaderCodec.decode(protectedB64);
    }

    private static void requireWire(OuterWireMessage wire) {
        if (wire == null) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, "wire must not be null");
        }
    }

    private static void requireNotBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, fieldName + " must not be blank");
        }
    }

    private static void requireBase64UrlNoPadding(String value, String fieldName) {
        if (!BASE64URL_NO_PADDING.matcher(value).matches()) {
            throw new ProtocolException(ErrorCode.INVALID_FIELD, fieldName + " must be base64url without padding");
        }
    }
}
