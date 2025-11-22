package com.windletter.protocol.jwe;

/**
 * Per-recipient header describing key wrapping algorithm and identifiers.
 * 描述密钥封装算法与标识的收件人头。
 */
public class RecipientHeader {
    private String kid;
    private String rid;
    private String alg;
    private Epk epk;

    public RecipientHeader() {
    }

    public RecipientHeader(String kid, String rid, String alg, Epk epk) {
        this.kid = kid;
        this.rid = rid;
        this.alg = alg;
        this.epk = epk;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getRid() {
        return rid;
    }

    public void setRid(String rid) {
        this.rid = rid;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public Epk getEpk() {
        return epk;
    }

    public void setEpk(Epk epk) {
        this.epk = epk;
    }
}
