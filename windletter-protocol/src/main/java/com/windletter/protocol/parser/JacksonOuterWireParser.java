package com.windletter.protocol.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.KidRef;
import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.RecipientEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Strict Jackson-based parser for Wind Letter outer wire transport JSON.
 */
public final class JacksonOuterWireParser implements OuterWireParser {

    private static final Set<String> OUTER_FIELDS = Set.of("protected", "aad", "recipients", "iv", "ciphertext", "tag");
    private static final Set<String> RECIPIENT_FIELDS = Set.of("kid", "rid", "ek", "encrypted_key");
    private static final Set<String> KID_FIELDS = Set.of("x25519", "mlkem768");

    private final ObjectMapper objectMapper;

    public JacksonOuterWireParser() {
        this.objectMapper = createStrictMapper(new ObjectMapper());
    }

    public JacksonOuterWireParser(ObjectMapper objectMapper) {
        if (objectMapper == null) {
            throw new IllegalArgumentException("objectMapper must not be null");
        }
        this.objectMapper = createStrictMapper(objectMapper.copy());
    }

    @Override
    public OuterWireMessage parse(String wireJson) {
        JsonNode rootNode = readRootNode(wireJson);
        if (!rootNode.isObject()) {
            throw malformedWire("outer wire root must be a JSON object");
        }
        ObjectNode root = (ObjectNode) rootNode;
        rejectUnknownFields(root, OUTER_FIELDS, "outer");

        String protectedB64 = requireStringField(root, "protected");
        String aadB64 = requireStringField(root, "aad");
        ArrayNode recipientsNode = requireArrayField(root, "recipients");
        String ivB64 = requireStringField(root, "iv");
        String ciphertextB64 = requireStringField(root, "ciphertext");
        String tagB64 = requireStringField(root, "tag");

        List<RecipientEntry> recipients = parseRecipients(recipientsNode);
        return new OuterWireMessage(protectedB64, aadB64, recipients, ivB64, ciphertextB64, tagB64);
    }

    private JsonNode readRootNode(String wireJson) {
        if (wireJson == null) {
            throw malformedWire("outer wire JSON must not be null");
        }
        try {
            return objectMapper.readTree(wireJson);
        } catch (JsonProcessingException e) {
            if (isDuplicateFieldError(e)) {
                throw malformedWire("outer wire JSON contains duplicate fields", e);
            }
            throw malformedWire("outer wire JSON is malformed", e);
        } catch (RuntimeException e) {
            throw malformedWire("failed to parse outer wire JSON", e);
        }
    }

    private List<RecipientEntry> parseRecipients(ArrayNode recipientsNode) {
        List<RecipientEntry> recipients = new ArrayList<>(recipientsNode.size());
        for (int i = 0; i < recipientsNode.size(); i++) {
            JsonNode recipientNode = recipientsNode.get(i);
            if (!recipientNode.isObject()) {
                throw invalidField("recipients[" + i + "] must be an object");
            }
            ObjectNode recipient = (ObjectNode) recipientNode;
            rejectUnknownFields(recipient, RECIPIENT_FIELDS, "recipients[" + i + "]");
            KidRef kid = parseKid(recipient.get("kid"), i);
            String rid = readOptionalString(recipient, "rid", "recipients[" + i + "].rid");
            String ek = readOptionalString(recipient, "ek", "recipients[" + i + "].ek");
            String encryptedKey = readOptionalString(recipient, "encrypted_key", "recipients[" + i + "].encrypted_key");
            recipients.add(new RecipientEntry(kid, rid, ek, encryptedKey));
        }
        return recipients;
    }

    private KidRef parseKid(JsonNode kidNode, int index) {
        if (kidNode == null) {
            return null;
        }
        if (kidNode.isNull()) {
            throw invalidField("field 'recipients[" + index + "].kid' must not be null");
        }
        if (!kidNode.isObject()) {
            throw invalidField("recipients[" + index + "].kid must be an object");
        }
        ObjectNode kidObject = (ObjectNode) kidNode;
        rejectUnknownFields(kidObject, KID_FIELDS, "recipients[" + index + "].kid");
        String x25519 = readOptionalString(kidObject, "x25519", "recipients[" + index + "].kid.x25519");
        String mlkem768 = readOptionalString(kidObject, "mlkem768", "recipients[" + index + "].kid.mlkem768");
        return new KidRef(x25519, mlkem768);
    }

    private String requireStringField(ObjectNode root, String field) {
        JsonNode node = requireField(root, field);
        if (!node.isTextual()) {
            throw invalidField("field '" + field + "' must be a string");
        }
        return node.textValue();
    }

    private ArrayNode requireArrayField(ObjectNode root, String field) {
        JsonNode node = requireField(root, field);
        if (!node.isArray()) {
            throw invalidField("field '" + field + "' must be an array");
        }
        return (ArrayNode) node;
    }

    private JsonNode requireField(ObjectNode root, String field) {
        if (!root.has(field)) {
            throw invalidField("missing required field '" + field + "'");
        }
        return root.get(field);
    }

    private String readOptionalString(ObjectNode parent, String field, String fieldPath) {
        if (!parent.has(field)) {
            return null;
        }
        JsonNode node = parent.get(field);
        if (node.isNull()) {
            throw invalidField("field '" + fieldPath + "' must not be null");
        }
        if (!node.isTextual()) {
            throw invalidField("field '" + fieldPath + "' must be a string");
        }
        return node.textValue();
    }

    private void rejectUnknownFields(ObjectNode objectNode, Set<String> allowedFields, String contextPath) {
        objectNode.fieldNames().forEachRemaining(fieldName -> {
            if (!allowedFields.contains(fieldName)) {
                throw invalidField("unknown field '" + contextPath + "." + fieldName + "'");
            }
        });
    }

    private static ProtocolException malformedWire(String message) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message);
    }

    private static ProtocolException malformedWire(String message, Throwable cause) {
        return new ProtocolException(ErrorCode.MALFORMED_WIRE, message, cause);
    }

    private static ProtocolException invalidField(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    private static ObjectMapper createStrictMapper(ObjectMapper mapper) {
        mapper.getFactory().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        return mapper;
    }

    private static boolean isDuplicateFieldError(JsonProcessingException exception) {
        Throwable current = exception;
        while (current != null) {
            String message = current.getMessage();
            if (message != null && message.contains("Duplicate field")) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
