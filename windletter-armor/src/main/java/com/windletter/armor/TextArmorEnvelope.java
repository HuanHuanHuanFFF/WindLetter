package com.windletter.armor;

/**
 * Text armor PGP-style envelope for base64url encoded JWE.
 * Base64URL JWE 的 PGP 风格文本装甲外壳。
 */
public class TextArmorEnvelope {
    private ArmorEncoding encoding;
    private String version;
    private String data;
    private String checksum;

    public TextArmorEnvelope() {
    }

    public TextArmorEnvelope(ArmorEncoding encoding, String version, String data, String checksum) {
        this.encoding = encoding;
        this.version = version;
        this.data = data;
        this.checksum = checksum;
    }

    public ArmorEncoding getEncoding() {
        return encoding;
    }

    public void setEncoding(ArmorEncoding encoding) {
        this.encoding = encoding;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }
}
