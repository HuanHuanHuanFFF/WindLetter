package com.windletter.protocol.jwe;

import com.windletter.protocol.WindMode;

/**
 * JWE protected header fields.
 * JWE 受保护头字段。
 */
public class JweProtectedHeader {
    private String typ;
    private String cty;
    private String ver;
    private WindMode windMode;
    private String enc;
    private String zip;

    public JweProtectedHeader() {
    }

    public JweProtectedHeader(String typ, String cty, String ver, WindMode windMode, String enc, String zip) {
        this.typ = typ;
        this.cty = cty;
        this.ver = ver;
        this.windMode = windMode;
        this.enc = enc;
        this.zip = zip;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getCty() {
        return cty;
    }

    public void setCty(String cty) {
        this.cty = cty;
    }

    public String getVer() {
        return ver;
    }

    public void setVer(String ver) {
        this.ver = ver;
    }

    public WindMode getWindMode() {
        return windMode;
    }

    public void setWindMode(WindMode windMode) {
        this.windMode = windMode;
    }

    public String getEnc() {
        return enc;
    }

    public void setEnc(String enc) {
        this.enc = enc;
    }

    public String getZip() {
        return zip;
    }

    public void setZip(String zip) {
        this.zip = zip;
    }
}
