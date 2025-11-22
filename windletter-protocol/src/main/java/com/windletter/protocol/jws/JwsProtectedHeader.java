package com.windletter.protocol.jws;

/**
 * Protected header for inner JWS.
 * 内层 JWS 的受保护头。
 */
public class JwsProtectedHeader {
    private String typ;
    private String alg;
    private String kid;
    private Long ts;
    private String pht;
    private String rch;

    public JwsProtectedHeader() {
    }

    public JwsProtectedHeader(String typ, String alg, String kid, Long ts, String pht, String rch) {
        this.typ = typ;
        this.alg = alg;
        this.kid = kid;
        this.ts = ts;
        this.pht = pht;
        this.rch = rch;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public Long getTs() {
        return ts;
    }

    public void setTs(Long ts) {
        this.ts = ts;
    }

    public String getPht() {
        return pht;
    }

    public void setPht(String pht) {
        this.pht = pht;
    }

    public String getRch() {
        return rch;
    }

    public void setRch(String rch) {
        this.rch = rch;
    }
}
