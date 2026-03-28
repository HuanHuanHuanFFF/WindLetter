package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ObfuscationSenderInfo;
import com.windletter.protocol.wire.ProtectedCore;
import com.windletter.protocol.wire.RecipientEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class ObfuscationOuterBranchParser {

    private static final Set<String> EPK_FIELDS = Set.of("kty", "crv", "x");
    private static final Set<String> RECIPIENT_X25519_FIELDS = Set.of("rid", "encrypted_key");
    private static final Set<String> RECIPIENT_HYBRID_FIELDS = Set.of("rid", "ek", "encrypted_key");

    BranchParseResult parse(ProtectedCore core, JsonNode protectedNode, JsonNode recipientsNode) {
        ParserSupport.requireAbsent(protectedNode, "kid", "outer.protected");

        JsonNode epkNode = ParserSupport.requireObjectField(protectedNode, "epk", "outer.protected");
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
        ParserSupport.assertKnownFields(epkNode, EPK_FIELDS, "outer.protected.epk");

        List<RecipientEntry> recipients = new ArrayList<>();
        if (ParserSupport.ALG_X25519.equals(core.keyAlg())) {
            parseX25519Recipients(recipientsNode, recipients);
        } else {
            parseHybridRecipients(recipientsNode, recipients);
        }

        return new BranchParseResult(new ObfuscationSenderInfo(kty, crv, epkX), recipients);
    }

    private void parseX25519Recipients(JsonNode recipientsNode, List<RecipientEntry> recipients) {
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }

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
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_X25519_FIELDS, "outer.recipients[" + i + "]");

            recipients.add(new ObfuscationRecipient(rid, encryptedKey, null));
        }
    }

    private void parseHybridRecipients(JsonNode recipientsNode, List<RecipientEntry> recipients) {
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }

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
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_HYBRID_FIELDS, "outer.recipients[" + i + "]");

            recipients.add(new ObfuscationRecipient(rid, encryptedKey, ek));
        }
    }
}
