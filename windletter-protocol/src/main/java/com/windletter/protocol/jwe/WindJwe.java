package com.windletter.protocol.jwe;

import java.util.ArrayList;
import java.util.List;

/**
 * Outer JWE object that is the only transmitted JSON on the wire.
 * 唯一在网络上传输的外层 JWE 对象。
 */
public class WindJwe {
    private String protectedB64;
    private String aad;
    private List<Recipient> recipients = new ArrayList<>();
    private String iv;
    private String ciphertext;
    private String tag;

    public WindJwe() {
    }

    public WindJwe(String protectedB64, String aad, List<Recipient> recipients, String iv, String ciphertext, String tag) {
        this.protectedB64 = protectedB64;
        this.aad = aad;
        if (recipients != null) {
            this.recipients = recipients;
        }
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.tag = tag;
    }

    public String getProtectedB64() {
        return protectedB64;
    }

    public void setProtectedB64(String protectedB64) {
        this.protectedB64 = protectedB64;
    }

    public String getAad() {
        return aad;
    }

    public void setAad(String aad) {
        this.aad = aad;
    }

    public List<Recipient> getRecipients() {
        return recipients;
    }

    public void setRecipients(List<Recipient> recipients) {
        this.recipients = recipients;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }
}
