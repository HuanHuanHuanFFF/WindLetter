package com.windletter.protocol.jwe;

/**
 * Ephemeral public key for ECDH-ES.
 * 用于 ECDH-ES 的临时公钥。
 */
public class Epk {
    private String kty;
    private String crv;
    private String x;

    public Epk() {
    }

    public Epk(String kty, String crv, String x) {
        this.kty = kty;
        this.crv = crv;
        this.x = x;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX() {
        return x;
    }

    public void setX(String x) {
        this.x = x;
    }
}
