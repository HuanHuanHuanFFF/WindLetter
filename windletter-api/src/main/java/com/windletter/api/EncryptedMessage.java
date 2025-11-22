package com.windletter.api;

import com.windletter.protocol.jwe.WindJwe;

/**
 * Holder for serialized JWE and optional armor representations.
 * 保存序列化后的 JWE 以及可选的装甲表示。
 */
public class EncryptedMessage {
    private WindJwe jwe;
    private String jweJson;
    private String armor;

    public EncryptedMessage() {
    }

    public EncryptedMessage(WindJwe jwe, String jweJson, String armor) {
        this.jwe = jwe;
        this.jweJson = jweJson;
        this.armor = armor;
    }

    public WindJwe getJwe() {
        return jwe;
    }

    public void setJwe(WindJwe jwe) {
        this.jwe = jwe;
    }

    public String getJweJson() {
        return jweJson;
    }

    public void setJweJson(String jweJson) {
        this.jweJson = jweJson;
    }

    public String getArmor() {
        return armor;
    }

    public void setArmor(String armor) {
        this.armor = armor;
    }
}
