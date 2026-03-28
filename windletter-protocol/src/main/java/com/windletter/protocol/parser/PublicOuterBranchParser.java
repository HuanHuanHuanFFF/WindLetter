package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.ProtectedCore;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.PublicSenderInfo;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class PublicOuterBranchParser {

    private static final Set<String> KID_FIELDS = Set.of("x25519", "mlkem768");
    private static final Set<String> RECIPIENT_X25519_FIELDS = Set.of("kid", "encrypted_key");
    private static final Set<String> RECIPIENT_HYBRID_FIELDS = Set.of("kid", "ek", "encrypted_key");

    BranchParseResult parse(ProtectedCore core, JsonNode protectedNode, JsonNode recipientsNode) {
        ParserSupport.requireAbsent(protectedNode, "epk", "outer.protected");

        JsonNode senderKidNode = ParserSupport.requireObjectField(protectedNode, "kid", "outer.protected");
        String senderKidX25519 = ParserSupport.requireText(senderKidNode, "x25519", "outer.protected.kid");
        ParserSupport.requireLength(
                ParserSupport.decodeBase64UrlStrict(senderKidX25519, "outer.protected.kid.x25519"),
                ParserSupport.LEN_KID,
                "outer.protected.kid.x25519"
        );
        if (senderKidNode.has("mlkem768")) {
            throw ParserSupport.invalidField("outer.protected.kid.mlkem768 must be absent");
        }
        ParserSupport.assertKnownFields(senderKidNode, KID_FIELDS, "outer.protected.kid");

        List<RecipientEntry> recipients = new ArrayList<>();
        if (ParserSupport.ALG_X25519.equals(core.keyAlg())) {
            parseX25519Recipients(recipientsNode, recipients);
        } else {
            parseHybridRecipients(recipientsNode, recipients);
        }

        return new BranchParseResult(new PublicSenderInfo(senderKidX25519), recipients);
    }

    private void parseX25519Recipients(JsonNode recipientsNode, List<RecipientEntry> recipients) {
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }
            JsonNode kidNode = ParserSupport.requireObjectField(recipientNode, "kid", "outer.recipients[" + i + "]");

            String x25519Kid = ParserSupport.requireText(kidNode, "x25519", "outer.recipients[" + i + "].kid");
            ParserSupport.requireLength(
                    ParserSupport.decodeBase64UrlStrict(x25519Kid, "outer.recipients[" + i + "].kid.x25519"),
                    ParserSupport.LEN_KID,
                    "outer.recipients[" + i + "].kid.x25519"
            );
            if (kidNode.has("mlkem768")) {
                throw ParserSupport.invalidField("outer.recipients[" + i + "].kid.mlkem768 must be absent");
            }

            byte[] encryptedKey = ParserSupport.decodeBase64UrlStrict(
                    ParserSupport.requireText(recipientNode, "encrypted_key", "outer.recipients[" + i + "]"),
                    "outer.recipients[" + i + "].encrypted_key"
            );
            ParserSupport.requireLength(encryptedKey, ParserSupport.LEN_A256KW_WRAPPED_CEK,
                    "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.requireAbsent(recipientNode, "ek", "outer.recipients[" + i + "]");
            ParserSupport.assertKnownFields(kidNode, KID_FIELDS, "outer.recipients[" + i + "].kid");
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_X25519_FIELDS, "outer.recipients[" + i + "]");

            recipients.add(new PublicRecipient(
                    new RecipientKid(x25519Kid, null),
                    encryptedKey,
                    null
            ));
        }
    }

    private void parseHybridRecipients(JsonNode recipientsNode, List<RecipientEntry> recipients) {
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }
            JsonNode kidNode = ParserSupport.requireObjectField(recipientNode, "kid", "outer.recipients[" + i + "]");

            String x25519Kid = ParserSupport.requireText(kidNode, "x25519", "outer.recipients[" + i + "].kid");
            String mlkem768Kid = ParserSupport.requireText(kidNode, "mlkem768", "outer.recipients[" + i + "].kid");
            ParserSupport.requireLength(
                    ParserSupport.decodeBase64UrlStrict(x25519Kid, "outer.recipients[" + i + "].kid.x25519"),
                    ParserSupport.LEN_KID,
                    "outer.recipients[" + i + "].kid.x25519"
            );
            ParserSupport.requireLength(
                    ParserSupport.decodeBase64UrlStrict(mlkem768Kid, "outer.recipients[" + i + "].kid.mlkem768"),
                    ParserSupport.LEN_KID,
                    "outer.recipients[" + i + "].kid.mlkem768"
            );

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
            ParserSupport.assertKnownFields(kidNode, KID_FIELDS, "outer.recipients[" + i + "].kid");
            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_HYBRID_FIELDS, "outer.recipients[" + i + "]");

            recipients.add(new PublicRecipient(
                    new RecipientKid(x25519Kid, mlkem768Kid),
                    encryptedKey,
                    ek
            ));
        }
    }
}
