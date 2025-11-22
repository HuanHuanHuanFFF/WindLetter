package com.windletter.api;

import com.windletter.protocol.payload.WindPayload;

/**
 * Result of decrypt-and-verify flow.
 * 解密并验签流程的结果载体。
 */
public class DecryptResult {
    private WindPayload payload;
    private String senderKid;
    private boolean signatureValid;
    private String algorithmProfile;

    public DecryptResult() {
    }

    public DecryptResult(WindPayload payload, String senderKid, boolean signatureValid, String algorithmProfile) {
        this.payload = payload;
        this.senderKid = senderKid;
        this.signatureValid = signatureValid;
        this.algorithmProfile = algorithmProfile;
    }

    public WindPayload getPayload() {
        return payload;
    }

    public void setPayload(WindPayload payload) {
        this.payload = payload;
    }

    public String getSenderKid() {
        return senderKid;
    }

    public void setSenderKid(String senderKid) {
        this.senderKid = senderKid;
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public String getAlgorithmProfile() {
        return algorithmProfile;
    }

    public void setAlgorithmProfile(String algorithmProfile) {
        this.algorithmProfile = algorithmProfile;
    }
}
