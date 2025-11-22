package com.windletter.protocol.jwe;

/**
 * Recipient entry binding header and wrapped CEK.
 * 绑定收件人头与封装 CEK 的条目。
 */
public class Recipient {
    private RecipientHeader header;
    private String encryptedKey;

    public Recipient() {
    }

    public Recipient(RecipientHeader header, String encryptedKey) {
        this.header = header;
        this.encryptedKey = encryptedKey;
    }

    public RecipientHeader getHeader() {
        return header;
    }

    public void setHeader(RecipientHeader header) {
        this.header = header;
    }

    public String getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(String encryptedKey) {
        this.encryptedKey = encryptedKey;
    }
}
