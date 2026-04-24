package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderKid;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class PublicOuterBranchParser {

    private static final Set<String> KID_FIELDS = Set.of("x25519", "mlkem768");
    private static final Set<String> RECIPIENT_FIELDS = Set.of("kid", "ek", "encrypted_key");

    BranchParseResult parse(String keyAlg, JsonNode protectedNode, JsonNode recipientsNode) {
        ParserSupport.precheckOptionalObjectShape(protectedNode, "kid", "outer.protected.kid");
        JsonNode senderKidNode = protectedNode.get("kid");
        if (senderKidNode != null) {
            ParserSupport.precheckOptionalTextShape(senderKidNode, "x25519", "outer.protected.kid.x25519");
            ParserSupport.precheckOptionalTextShape(senderKidNode, "mlkem768", "outer.protected.kid.mlkem768");
            ParserSupport.precheckOptionalBase64TextField(senderKidNode, "x25519", "outer.protected.kid.x25519");
            ParserSupport.precheckOptionalBase64TextField(senderKidNode, "mlkem768", "outer.protected.kid.mlkem768");
        }

        if (senderKidNode != null) {
            ParserSupport.assertKnownFields(senderKidNode, KID_FIELDS, "outer.protected.kid");
        }

        ParserSupport.requireAbsent(protectedNode, "epk", "outer.protected");
        senderKidNode = ParserSupport.requireObjectField(protectedNode, "kid", "outer.protected");
        String senderKidX25519 = ParserSupport.requireText(senderKidNode, "x25519", "outer.protected.kid");
        ParserSupport.requireLength(
                ParserSupport.decodeBase64UrlStrict(senderKidX25519, "outer.protected.kid.x25519"),
                ParserSupport.LEN_KID,
                "outer.protected.kid.x25519"
        );
        if (senderKidNode.has("mlkem768")) {
            throw ParserSupport.invalidField("outer.protected.kid.mlkem768 must be absent");
        }

        List<RecipientEntry> recipients;
        if (ParserSupport.ALG_X25519.equals(keyAlg)) {
            recipients = parseX25519Recipients(recipientsNode);
        } else if (ParserSupport.ALG_HYBRID.equals(keyAlg)) {
            recipients = parseHybridRecipients(recipientsNode);
        } else {
            throw ParserSupport.internalError("unreachable public key_alg dispatch: " + keyAlg);
        }
        return new BranchParseResult(new SenderKid(senderKidX25519), recipients);
    }

    private List<RecipientEntry> parseX25519Recipients(JsonNode recipientsNode) {
        List<RecipientEntry> recipients = new ArrayList<>();
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw ParserSupport.malformed("outer.recipients[" + i + "] must be a JSON object");
            }

            ParserSupport.precheckOptionalObjectShape(recipientNode, "kid", "outer.recipients[" + i + "].kid");
            ParserSupport.precheckOptionalTextShape(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalTextShape(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "ek", "outer.recipients[" + i + "].ek");

            JsonNode kidNode = recipientNode.get("kid");
            if (kidNode != null) {
                ParserSupport.precheckOptionalTextShape(kidNode, "x25519", "outer.recipients[" + i + "].kid.x25519");
                ParserSupport.precheckOptionalTextShape(kidNode, "mlkem768", "outer.recipients[" + i + "].kid.mlkem768");
                ParserSupport.precheckOptionalBase64TextField(kidNode, "x25519", "outer.recipients[" + i + "].kid.x25519");
                ParserSupport.precheckOptionalBase64TextField(kidNode, "mlkem768", "outer.recipients[" + i + "].kid.mlkem768");
            }

            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_FIELDS, "outer.recipients[" + i + "]");
            if (kidNode != null) {
                ParserSupport.assertKnownFields(kidNode, KID_FIELDS, "outer.recipients[" + i + "].kid");
            }

            kidNode = ParserSupport.requireObjectField(recipientNode, "kid", "outer.recipients[" + i + "]");

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
            recipients.add(new PublicRecipient(
                    new RecipientKid(x25519Kid, null),
                    encryptedKey,
                    null
            ));
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

            ParserSupport.precheckOptionalObjectShape(recipientNode, "kid", "outer.recipients[" + i + "].kid");
            ParserSupport.precheckOptionalTextShape(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalTextShape(recipientNode, "ek", "outer.recipients[" + i + "].ek");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "encrypted_key", "outer.recipients[" + i + "].encrypted_key");
            ParserSupport.precheckOptionalBase64TextField(recipientNode, "ek", "outer.recipients[" + i + "].ek");

            JsonNode kidNode = recipientNode.get("kid");
            if (kidNode != null) {
                ParserSupport.precheckOptionalTextShape(kidNode, "x25519", "outer.recipients[" + i + "].kid.x25519");
                ParserSupport.precheckOptionalTextShape(kidNode, "mlkem768", "outer.recipients[" + i + "].kid.mlkem768");
                ParserSupport.precheckOptionalBase64TextField(kidNode, "x25519", "outer.recipients[" + i + "].kid.x25519");
                ParserSupport.precheckOptionalBase64TextField(kidNode, "mlkem768", "outer.recipients[" + i + "].kid.mlkem768");
            }

            ParserSupport.assertKnownFields(recipientNode, RECIPIENT_FIELDS, "outer.recipients[" + i + "]");
            if (kidNode != null) {
                ParserSupport.assertKnownFields(kidNode, KID_FIELDS, "outer.recipients[" + i + "].kid");
            }

            kidNode = ParserSupport.requireObjectField(recipientNode, "kid", "outer.recipients[" + i + "]");

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
            recipients.add(new PublicRecipient(
                    new RecipientKid(x25519Kid, mlkem768Kid),
                    encryptedKey,
                    ek
            ));
        }
        return recipients;
    }
}
