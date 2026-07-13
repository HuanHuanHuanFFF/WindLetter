package com.windletter.protocol.codec;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderInfo;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;

import java.util.List;

/**
 * Typed outer-wire model to JSON projection shared by canonicalization and writing.
 */
public final class OuterJsonMapper {

    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

    private OuterJsonMapper() {
    }

    public static ObjectNode toProtectedJson(ProtectedHeader header) {
        if (header == null) {
            throw new IllegalArgumentException("header must not be null");
        }

        ObjectNode value = JSON.objectNode();
        value.put("typ", header.typ());
        value.put("cty", header.cty());
        value.put("ver", header.ver());
        value.put("wind_mode", header.windMode());
        value.put("enc", header.enc());
        value.put("key_alg", header.keyAlg());
        addSenderInfo(value, header.senderInfo());
        return value;
    }

    public static ArrayNode toRecipientsJson(List<? extends RecipientEntry> recipients) {
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }

        ArrayNode values = JSON.arrayNode();
        for (RecipientEntry recipient : recipients) {
            if (recipient == null) {
                throw new IllegalArgumentException("recipient must not be null");
            }
            values.add(toRecipientJson(recipient));
        }
        return values;
    }

    public static ObjectNode toOuterJson(WindLetter letter) {
        if (letter == null) {
            throw new IllegalArgumentException("letter must not be null");
        }

        ObjectNode value = JSON.objectNode();
        value.put("protected", letter.protectedValue());
        value.put("aad", letter.aad());
        value.set("recipients", toRecipientsJson(letter.recipients()));
        value.put("iv", Base64Url.encode(letter.iv()));
        value.put("ciphertext", Base64Url.encode(letter.ciphertext()));
        value.put("tag", Base64Url.encode(letter.tag()));
        return value;
    }

    private static void addSenderInfo(ObjectNode protectedValue, SenderInfo senderInfo) {
        if (senderInfo instanceof SenderKid senderKid) {
            ObjectNode kid = JSON.objectNode();
            kid.put("x25519", senderKid.x25519());
            protectedValue.set("kid", kid);
            return;
        }
        if (senderInfo instanceof Epk epk) {
            ObjectNode epkValue = JSON.objectNode();
            epkValue.put("kty", epk.kty());
            epkValue.put("crv", epk.crv());
            epkValue.put("x", Base64Url.encode(epk.x()));
            protectedValue.set("epk", epkValue);
            return;
        }
        throw new IllegalArgumentException("unsupported sender info type");
    }

    private static ObjectNode toRecipientJson(RecipientEntry recipient) {
        if (recipient instanceof PublicRecipient publicRecipient) {
            return toPublicRecipientJson(publicRecipient);
        }
        if (recipient instanceof ObfuscationRecipient obfuscationRecipient) {
            return toObfuscationRecipientJson(obfuscationRecipient);
        }
        throw new IllegalArgumentException("unsupported recipient type");
    }

    private static ObjectNode toPublicRecipientJson(PublicRecipient recipient) {
        ObjectNode value = JSON.objectNode();
        value.set("kid", toRecipientKidJson(recipient.kid()));
        value.put("encrypted_key", Base64Url.encode(recipient.encryptedKey()));
        if (recipient.ek() != null) {
            value.put("ek", Base64Url.encode(recipient.ek()));
        }
        return value;
    }

    private static ObjectNode toRecipientKidJson(RecipientKid recipientKid) {
        ObjectNode value = JSON.objectNode();
        value.put("x25519", recipientKid.x25519());
        if (recipientKid.mlkem768() != null) {
            value.put("mlkem768", recipientKid.mlkem768());
        }
        return value;
    }

    private static ObjectNode toObfuscationRecipientJson(ObfuscationRecipient recipient) {
        ObjectNode value = JSON.objectNode();
        value.put("rid", Base64Url.encode(recipient.rid()));
        value.put("encrypted_key", Base64Url.encode(recipient.encryptedKey()));
        if (recipient.ek() != null) {
            value.put("ek", Base64Url.encode(recipient.ek()));
        }
        return value;
    }
}
