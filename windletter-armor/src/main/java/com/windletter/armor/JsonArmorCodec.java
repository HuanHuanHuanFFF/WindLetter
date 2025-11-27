package com.windletter.armor;

import com.windletter.protocol.util.JsonUtil;

/**
 * Codec for JSON armor wrapper.
 * JSON 装甲编码/解码器。
 */
public class JsonArmorCodec {

    public String toArmor(ArmorJsonEnvelope envelope) {
        if (envelope == null) {
            throw new IllegalArgumentException("envelope is null");
        }
        return JsonUtil.toJson(envelope);
    }

    public ArmorJsonEnvelope fromArmor(String armorText) {
        if (armorText == null) {
            throw new IllegalArgumentException("armor text is null");
        }
        return JsonUtil.fromJson(armorText, ArmorJsonEnvelope.class);
    }
}
