package com.windletter.armor;

/**
 * JSON Armor wrapper for chat/display scenarios.
 * 聊天/展示场景的 JSON 装甲外壳。
 */
public class ArmorJsonEnvelope {
    private String type;
    private String encoding;
    private String v;
    private String data;
    private String checksum;

    public ArmorJsonEnvelope() {
    }

    public ArmorJsonEnvelope(String type, String encoding, String v, String data, String checksum) {
        this.type = type;
        this.encoding = encoding;
        this.v = v;
        this.data = data;
        this.checksum = checksum;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public String getV() {
        return v;
    }

    public void setV(String v) {
        this.v = v;
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
