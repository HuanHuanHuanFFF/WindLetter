package com.windletter.armor;

/**
 * Codec for text armor PGP-style blocks.
 * 文本装甲（PGP 风格）的编解码器。
 */
public class TextArmorCodec {
    public String toArmor(TextArmorEnvelope envelope) {
        throw new UnsupportedOperationException("Text armor serialization not yet implemented");
    }

    public TextArmorEnvelope fromArmor(String armorText) {
        throw new UnsupportedOperationException("Text armor parsing not yet implemented");
    }
}
