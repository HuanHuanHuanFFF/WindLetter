package com.windletter.armor;

import java.util.ArrayList;
import java.util.List;

/**
 * Codec for text armor PGP-style blocks.
 * 文本装甲（PGP 风格）的编解码器。
 */
public class TextArmorCodec {
    public String toArmor(TextArmorEnvelope envelope) {
        if (envelope == null) {
            throw new IllegalArgumentException("envelope is null");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN WIND LETTER-----\n");
        sb.append("Armor: ").append(envelope.getEncoding().jsonValue()).append("; v=").append(envelope.getVersion()).append("\n");
        sb.append(envelope.getData()).append("\n");
        if (envelope.getChecksum() != null && !envelope.getChecksum().isEmpty()) {
            sb.append("=").append(envelope.getChecksum()).append("\n");
        }
        sb.append("-----END WIND LETTER-----");
        return sb.toString();
    }

    public TextArmorEnvelope fromArmor(String armorText) {
        if (armorText == null) {
            throw new IllegalArgumentException("armor text is null");
        }
        String[] lines = armorText.replace("\r", "").split("\n");
        List<String> list = new ArrayList<>();
        for (String l : lines) {
            if (!l.isEmpty()) {
                list.add(l.trim());
            }
        }
        if (list.size() < 3 || !list.get(0).equals("-----BEGIN WIND LETTER-----")) {
            throw new IllegalArgumentException("Invalid armor header");
        }
        String header = list.get(1);
        if (!header.startsWith("Armor:")) {
            throw new IllegalArgumentException("Missing Armor header");
        }
        String encoding = null;
        String version = null;
        String[] parts = header.substring("Armor:".length()).split(";");
        for (String p : parts) {
            String trimmed = p.trim();
            if (trimmed.startsWith("base64url") || trimmed.startsWith("windbase1024f")) {
                encoding = trimmed.split("\\s")[0];
            }
            if (trimmed.startsWith("v=")) {
                version = trimmed.substring(2);
            } else if (trimmed.startsWith("v")) {
                String[] kv = trimmed.split("=", 2);
                if (kv.length == 2) {
                    version = kv[1];
                }
            }
        }
        String data = null;
        String checksum = null;
        for (int i = 2; i < list.size(); i++) {
            String l = list.get(i);
            if (l.startsWith("=")) {
                checksum = l.substring(1);
            } else if (l.startsWith("-----END WIND LETTER-----")) {
                break;
            } else {
                data = l;
            }
        }
        if (encoding == null || version == null || data == null) {
            throw new IllegalArgumentException("Invalid armor body");
        }
        ArmorEncoding enc = encoding.equalsIgnoreCase(ArmorEncoding.WINDBASE1024F.jsonValue())
                ? ArmorEncoding.WINDBASE1024F
                : ArmorEncoding.BASE64URL;
        return new TextArmorEnvelope(enc, version, data, checksum);
    }
}
