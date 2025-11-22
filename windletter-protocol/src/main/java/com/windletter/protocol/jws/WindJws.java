package com.windletter.protocol.jws;

/**
 * Inner JWS structure carrying protected header, payload, and signature.
 * 内层 JWS 结构，包含受保护头、载荷与签名。
 */
public class WindJws {
    private String protectedB64;
    private String payloadB64;
    private String signatureB64;

    public WindJws() {
    }

    public WindJws(String protectedB64, String payloadB64, String signatureB64) {
        this.protectedB64 = protectedB64;
        this.payloadB64 = payloadB64;
        this.signatureB64 = signatureB64;
    }

    public String getProtectedB64() {
        return protectedB64;
    }

    public void setProtectedB64(String protectedB64) {
        this.protectedB64 = protectedB64;
    }

    public String getPayloadB64() {
        return payloadB64;
    }

    public void setPayloadB64(String payloadB64) {
        this.payloadB64 = payloadB64;
    }

    public String getSignatureB64() {
        return signatureB64;
    }

    public void setSignatureB64(String signatureB64) {
        this.signatureB64 = signatureB64;
    }
}
