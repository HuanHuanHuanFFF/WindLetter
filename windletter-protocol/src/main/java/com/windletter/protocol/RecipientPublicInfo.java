package com.windletter.protocol;

/**
 * Recipient public key metadata for building recipients array.
 * 构造 recipients 数组所需的收件人公钥元数据。
 */
public class RecipientPublicInfo {
    private String kid;
    private String alg;
    private byte[] publicKeyBytes;

    public RecipientPublicInfo() {
    }

    public RecipientPublicInfo(String kid, String alg, byte[] publicKeyBytes) {
        this.kid = kid;
        this.alg = alg;
        this.publicKeyBytes = publicKeyBytes;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void setPublicKeyBytes(byte[] publicKeyBytes) {
        this.publicKeyBytes = publicKeyBytes;
    }
}
