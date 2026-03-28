package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.protocol.wire.OuterData;
import com.windletter.protocol.wire.OuterShell;
import com.windletter.protocol.wire.ProtectedCore;
import com.windletter.protocol.wire.ProtectedHeader;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Strict outer wire parser entry.
 */
public final class JacksonOuterWireParser implements OuterWireParser {

    private static final Set<String> OUTER_FIELDS = Set.of(
            "protected", "aad", "recipients", "iv", "ciphertext", "tag"
    );
    private static final Set<String> PROTECTED_FIELDS = Set.of(
            "typ", "cty", "ver", "wind_mode", "enc", "key_alg", "kid", "epk"
    );

    private final ObjectMapper mapper;
    private final PublicOuterBranchParser publicBranchParser;
    private final ObfuscationOuterBranchParser obfuscationBranchParser;

    public JacksonOuterWireParser() {
        this(new ObjectMapper(), new PublicOuterBranchParser(), new ObfuscationOuterBranchParser());
    }

    JacksonOuterWireParser(
            ObjectMapper mapper,
            PublicOuterBranchParser publicBranchParser,
            ObfuscationOuterBranchParser obfuscationBranchParser
    ) {
        this.mapper = mapper;
        this.publicBranchParser = publicBranchParser;
        this.obfuscationBranchParser = obfuscationBranchParser;
    }

    @Override
    public OuterData parse(String wireJson) {
        if (wireJson == null || wireJson.isBlank()) {
            throw ParserSupport.malformed("wireJson must be valid JSON");
        }

        JsonNode outerNode = ParserSupport.parseJsonObject(mapper, wireJson, "outer json");
        String protectedValue = ParserSupport.requireText(outerNode, "protected", "outer");
        byte[] protectedBytes = ParserSupport.decodeBase64UrlStrict(protectedValue, "outer.protected");
        JsonNode protectedNode = ParserSupport.parseJsonObject(
                mapper,
                new String(protectedBytes, StandardCharsets.UTF_8),
                "outer.protected"
        );

        precheckTopLevelStructureAndSyntax(outerNode);
        ProtectedCore core = parseCoreByPriority(protectedNode);

        String aad = ParserSupport.requireText(outerNode, "aad", "outer");
        ParserSupport.decodeBase64UrlStrict(aad, "outer.aad");
        byte[] iv = ParserSupport.decodeBase64UrlStrict(
                ParserSupport.requireText(outerNode, "iv", "outer"),
                "outer.iv"
        );
        ParserSupport.requireLength(iv, ParserSupport.LEN_GCM_IV, "outer.iv");
        byte[] ciphertext = ParserSupport.decodeBase64UrlStrict(
                ParserSupport.requireText(outerNode, "ciphertext", "outer"),
                "outer.ciphertext"
        );
        byte[] tag = ParserSupport.decodeBase64UrlStrict(
                ParserSupport.requireText(outerNode, "tag", "outer"),
                "outer.tag"
        );
        ParserSupport.requireLength(tag, ParserSupport.LEN_GCM_TAG, "outer.tag");
        JsonNode recipientsNode = ParserSupport.requireArrayField(outerNode, "recipients", "outer");
        if (recipientsNode.isEmpty()) {
            throw ParserSupport.invalidField("outer.recipients must not be empty");
        }

        BranchParseResult branchResult = ParserSupport.MODE_PUBLIC.equals(core.windMode())
                ? publicBranchParser.parse(core, protectedNode, recipientsNode)
                : obfuscationBranchParser.parse(core, protectedNode, recipientsNode);

        ParserSupport.assertKnownFields(outerNode, OUTER_FIELDS, "outer");
        ParserSupport.assertKnownFields(protectedNode, PROTECTED_FIELDS, "outer.protected");

        return new OuterData(
                new OuterShell(protectedValue, aad, iv, ciphertext, tag),
                new ProtectedHeader(core, branchResult.senderInfo()),
                branchResult.recipients()
        );
    }

    private static ProtectedCore parseCoreByPriority(JsonNode protectedNode) {
        String ver = ParserSupport.requireText(protectedNode, "ver", "outer.protected");
        if (!"1.0".equals(ver)) {
            throw ParserSupport.unsupportedVersion("unsupported outer.protected.ver: " + ver);
        }
        String enc = ParserSupport.requireText(protectedNode, "enc", "outer.protected");
        if (!ParserSupport.ENC_A256GCM.equals(enc)) {
            throw ParserSupport.unsupportedAlgorithm("unsupported outer.protected.enc: " + enc);
        }
        String keyAlg = ParserSupport.requireText(protectedNode, "key_alg", "outer.protected");
        if (!ParserSupport.ALG_X25519.equals(keyAlg) && !ParserSupport.ALG_HYBRID.equals(keyAlg)) {
            throw ParserSupport.unsupportedAlgorithm("unsupported outer.protected.key_alg: " + keyAlg);
        }
        ProtectedCore core = new ProtectedCore(
                ParserSupport.requireText(protectedNode, "typ", "outer.protected"),
                ParserSupport.requireText(protectedNode, "cty", "outer.protected"),
                ver,
                ParserSupport.requireText(protectedNode, "wind_mode", "outer.protected"),
                enc,
                keyAlg
        );
        validateRemainingCoreFields(core);
        return core;
    }

    private static void validateRemainingCoreFields(ProtectedCore core) {
        if (!ParserSupport.TYP_WIND_JWE.equals(core.typ())) {
            throw ParserSupport.invalidField("outer.protected.typ must be wind+jwe");
        }
        if (!ParserSupport.CTY_WIND_JWS.equals(core.cty()) && !ParserSupport.CTY_WIND_INNER.equals(core.cty())) {
            throw ParserSupport.invalidField("outer.protected.cty must be wind+jws or wind+inner");
        }
        if (!ParserSupport.MODE_PUBLIC.equals(core.windMode()) && !ParserSupport.MODE_OBFUSCATION.equals(core.windMode())) {
            throw ParserSupport.invalidField("outer.protected.wind_mode must be public or obfuscation");
        }
    }

    private static void precheckTopLevelStructureAndSyntax(JsonNode outerNode) {
        precheckOptionalArrayShape(outerNode, "recipients", "outer");
        precheckOptionalBase64TextField(outerNode, "aad", "outer.aad");
        precheckOptionalBase64TextField(outerNode, "iv", "outer.iv");
        precheckOptionalBase64TextField(outerNode, "ciphertext", "outer.ciphertext");
        precheckOptionalBase64TextField(outerNode, "tag", "outer.tag");
    }

    private static void precheckOptionalArrayShape(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node != null && !node.isArray()) {
            throw ParserSupport.malformed(fieldPath + " must be a JSON array");
        }
    }

    private static void precheckOptionalBase64TextField(JsonNode parent, String fieldName, String fieldPath) {
        JsonNode node = parent.get(fieldName);
        if (node == null) {
            return;
        }
        if (!node.isTextual()) {
            throw ParserSupport.malformed(fieldPath + " must be a JSON string");
        }
        String text = node.asText();
        if (text.isBlank()) {
            return;
        }
        ParserSupport.decodeBase64UrlStrict(text, fieldPath);
    }
}
