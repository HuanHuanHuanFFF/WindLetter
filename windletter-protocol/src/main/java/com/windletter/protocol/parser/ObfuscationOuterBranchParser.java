package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.RecipientEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class ObfuscationOuterBranchParser {

    private static final Set<String> EPK_FIELDS = Set.of("kty", "crv", "x");
    private static final Set<String> RECIPIENT_FIELDS = Set.of("rid", "ek", "encrypted_key");

    BranchParseResult parse(String keyAlg, JsonNode protectedNode, JsonNode recipientsNode) {
        ParserSupport.precheckOptionalObjectShape(protectedNode, "epk", "outer.protected.epk");
        JsonNode epkNode = protectedNode.get("epk");
        if (epkNode != null) {
            ParserSupport.precheckOptionalTextShape(epkNode, "kty", "outer.protected.epk.kty");
            ParserSupport.precheckOptionalTextShape(epkNode, "crv", "outer.protected.epk.crv");
            ParserSupport.precheckOptionalTextShape(epkNode, "x", "outer.protected.epk.x");
            ParserSupport.precheckOptionalBase64TextField(epkNode, "x", "outer.protected.epk.x");
            ParserSupport.assertKnownFields(epkNode, EPK_FIELDS, "outer.protected.epk");
        }

        ParserSupport.requireAbsent(protectedNode, "kid", "outer.protected");
        epkNode = ParserSupport.requireObjectField(protectedNode, "epk", "outer.protected");
        String kty = ParserSupport.requireText(epkNode, "kty", "outer.protected.epk");
        if (!ParserSupport.EPK_KTY_OKP.equals(kty)) {
            throw ParserSupport.invalidField("outer.protected.epk.kty must be OKP");
        }
        String crv = ParserSupport.requireText(epkNode, "crv", "outer.protected.epk");
        if (!ParserSupport.EPK_CRV_X25519.equals(crv)) {
            throw ParserSupport.invalidField("outer.protected.epk.crv must be X25519");
        }
        byte[] epkX = ParserSupport.decodeBase64UrlStrict(
                ParserSupport.requireText(epkNode, "x", "outer.protected.epk"),
                "outer.protected.epk.x"
        );
        ParserSupport.requireLength(epkX, ParserSupport.LEN_X25519_PUB, "outer.protected.epk.x");

        List<RecipientEntry> recipients;
        if (ParserSupport.ALG_X25519.equals(keyAlg)) {
            recipients = parseX25519Recipients(recipientsNode);
        } else if (ParserSupport.ALG_HYBRID.equals(keyAlg)) {
            recipients = parseHybridRecipients(recipientsNode);
        } else {
            throw ParserSupport.internalError("unreachable obfuscation key_alg dispatch: " + keyAlg);
        }
        return new BranchParseResult(new Epk(kty, crv, epkX), recipients);
    }

    private List<RecipientEntry> parseX25519Recipients(JsonNode recipientsNode) {
        List<RecipientEntry> recipients = new ArrayList<>();
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }

            ParserSupport.precheckOptionalTextShape(recipientNode, "rid", "outer.recipients[" + i + "].rid");
            ParserSupport.precheckOptionalTextShape(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalTextShape(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "rid", "outer.recipients[" + i + "].rid");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_FIELDS, "outer.recipients[" + i + "]");

            byte[] rid = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "rid", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].rid"
            );
            ParserSupport.requireLength(rid, ParserSupport.LEN_RID, "outer.recipients[" + i + "].rid");

            byte[] encryptedKey = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "encrypted_key", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].encrypted_key"
            );
            ParserSupport.requireLength(encryptedKey, ParserSupport.LEN_A256KW_WRAPPED_CEK,
                    "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.requireAbsent(recipientNode, "ek", "outer.recipients[" + i + "]");

            recipients.add(new ObfuscationRecipient(rid, encryptedKey, null));
        }
        return recipients;
    }

    private List<RecipientEntry> parseHybridRecipients(JsonNode recipientsNode) {
        List<RecipientEntry> recipients = new ArrayList<>();
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }

            ParserSupport.precheckOptionalTextShape(recipientNode, "rid", "outer.recipients[" + i + "].rid");
            ParserSupport.precheckOptionalTextShape(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalTextShape(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "rid", "outer.recipients[" + i + "].rid");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_FIELDS, "outer.recipients[" + i + "]");

            byte[] rid = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "rid", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].rid"
            );
            ParserSupport.requireLength(rid, ParserSupport.LEN_RID, "outer.recipients[" + i + "].rid");

            byte[] ek = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "ek", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].ek"
            );
            ParserSupport.requireLength(ek, ParserSupport.LEN_MLKEM768_CIPHERTEXT,
                    "outer.recipients[" + i + "].ek");

            byte[] encryptedKey = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "encrypted_key", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].encrypted_key"
            );
            ParserSupport.requireLength(encryptedKey, ParserSupport.LEN_A256KW_WRAPPED_CEK,
                    "outer.recipients[" + i + "].encrypted_key");

            recipients.add(new ObfuscationRecipient(rid, encryptedKey, ek));
        }
        return recipients;
    }
}
