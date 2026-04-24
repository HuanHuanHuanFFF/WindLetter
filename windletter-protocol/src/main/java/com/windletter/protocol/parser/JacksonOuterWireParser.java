package com.windletter.protocol.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.WindLetter;

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
    public WindLetter parse(String wireJson) {
        if (wireJson == null || wireJson.isBlank()) {
            throw ParserSupport.malformed("wireJson must be valid JSON");
        }

        JsonNode outerNode = ParserSupport.parseJsonObject(mapper, wireJson, "outer json");
        precheckTopLevelStructureAndSyntax(outerNode);
        precheckTopLevelBase64Syntax(outerNode);

        String protectedValue = ParserSupport.requireText(outerNode, "protected", "outer");
        byte[] protectedBytes = ParserSupport.decodeBase64UrlStrict(protectedValue, "outer.protected");
        JsonNode protectedNode = ParserSupport.parseJsonObject(
                mapper,
                new String(protectedBytes, StandardCharsets.UTF_8),
                "outer.protected"
        );
        precheckProtectedStructureAndSyntax(protectedNode);

        validateCoreByPriority(protectedNode);

        ParserSupport.assertKnownFields(outerNode, OUTER_FIELDS, "outer");
        ParserSupport.assertKnownFields(protectedNode, PROTECTED_FIELDS, "outer.protected");

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

        String typ = ParserSupport.requireText(protectedNode, "typ", "outer.protected");
        String cty = ParserSupport.requireText(protectedNode, "cty", "outer.protected");
        String ver = ParserSupport.requireText(protectedNode, "ver", "outer.protected");
        String windMode = ParserSupport.requireText(protectedNode, "wind_mode", "outer.protected");
        String enc = ParserSupport.requireText(protectedNode, "enc", "outer.protected");
        String keyAlg = ParserSupport.requireText(protectedNode, "key_alg", "outer.protected");

        validateCoreWhitelist(typ, cty, windMode);

        BranchParseResult branchResult = parseBranch(windMode, keyAlg, protectedNode, recipientsNode);
        ProtectedHeader protectedHeader = new ProtectedHeader(typ, cty, ver, windMode, enc, keyAlg, branchResult.senderInfo());
        return new WindLetter(protectedHeader, protectedValue, aad, branchResult.recipients(), iv, ciphertext, tag);
    }

    private BranchParseResult parseBranch(String windMode, String keyAlg, JsonNode protectedNode, JsonNode recipientsNode) {
        if (ParserSupport.MODE_PUBLIC.equals(windMode)) {
            return publicBranchParser.parse(keyAlg, protectedNode, recipientsNode);
        }
        if (ParserSupport.MODE_OBFUSCATION.equals(windMode)) {
            return obfuscationBranchParser.parse(keyAlg, protectedNode, recipientsNode);
        }
        throw ParserSupport.internalError("unreachable wind_mode dispatch: " + windMode);
    }

    private static void validateCoreByPriority(JsonNode protectedNode) {
        String ver = ParserSupport.optionalTextRaw(protectedNode, "ver", "outer.protected");
        if (ver != null && !ver.isBlank() && !"1.0".equals(ver)) {
            throw ParserSupport.unsupportedVersion("unsupported outer.protected.ver: " + ver);
        }

        if ("1.0".equals(ver)) {
            String enc = ParserSupport.optionalTextRaw(protectedNode, "enc", "outer.protected");
            if (enc != null && !enc.isBlank() && !ParserSupport.ENC_A256GCM.equals(enc)) {
                throw ParserSupport.unsupportedAlgorithm("unsupported outer.protected.enc: " + enc);
            }

            String keyAlg = ParserSupport.optionalTextRaw(protectedNode, "key_alg", "outer.protected");
            if (keyAlg != null && !keyAlg.isBlank()
                    && !ParserSupport.ALG_X25519.equals(keyAlg)
                    && !ParserSupport.ALG_HYBRID.equals(keyAlg)) {
                throw ParserSupport.unsupportedAlgorithm("unsupported outer.protected.key_alg: " + keyAlg);
            }
        }

        String typ = ParserSupport.optionalTextRaw(protectedNode, "typ", "outer.protected");
        if (typ != null && !typ.isBlank() && !ParserSupport.TYP_WIND_JWE.equals(typ)) {
            throw ParserSupport.invalidField("outer.protected.typ must be wind+jwe");
        }

        String cty = ParserSupport.optionalTextRaw(protectedNode, "cty", "outer.protected");
        if (cty != null && !cty.isBlank()
                && !ParserSupport.CTY_WIND_JWS.equals(cty)
                && !ParserSupport.CTY_WIND_INNER.equals(cty)) {
            throw ParserSupport.invalidField("outer.protected.cty must be wind+jws or wind+inner");
        }

        String windMode = ParserSupport.optionalTextRaw(protectedNode, "wind_mode", "outer.protected");
        if (windMode != null && !windMode.isBlank()
                && !ParserSupport.MODE_PUBLIC.equals(windMode)
                && !ParserSupport.MODE_OBFUSCATION.equals(windMode)) {
            throw ParserSupport.invalidField("outer.protected.wind_mode must be public or obfuscation");
        }
    }

    private static void validateCoreWhitelist(String typ, String cty, String windMode) {
        if (!ParserSupport.TYP_WIND_JWE.equals(typ)) {
            throw ParserSupport.invalidField("outer.protected.typ must be wind+jwe");
        }
        if (!ParserSupport.CTY_WIND_JWS.equals(cty) && !ParserSupport.CTY_WIND_INNER.equals(cty)) {
            throw ParserSupport.invalidField("outer.protected.cty must be wind+jws or wind+inner");
        }
        if (!ParserSupport.MODE_PUBLIC.equals(windMode) && !ParserSupport.MODE_OBFUSCATION.equals(windMode)) {
            throw ParserSupport.invalidField("outer.protected.wind_mode must be public or obfuscation");
        }
    }

    private static void precheckTopLevelStructureAndSyntax(JsonNode outerNode) {
        ParserSupport.precheckOptionalTextShape(outerNode, "protected", "outer.protected");
        ParserSupport.precheckOptionalTextShape(outerNode, "aad", "outer.aad");
        ParserSupport.precheckOptionalArrayShape(outerNode, "recipients", "outer.recipients");
        ParserSupport.precheckOptionalTextShape(outerNode, "iv", "outer.iv");
        ParserSupport.precheckOptionalTextShape(outerNode, "ciphertext", "outer.ciphertext");
        ParserSupport.precheckOptionalTextShape(outerNode, "tag", "outer.tag");
    }

    private static void precheckTopLevelBase64Syntax(JsonNode outerNode) {
        ParserSupport.precheckOptionalBase64TextField(outerNode, "protected", "outer.protected");
        ParserSupport.precheckOptionalBase64TextField(outerNode, "aad", "outer.aad");
        ParserSupport.precheckOptionalBase64TextField(outerNode, "iv", "outer.iv");
        ParserSupport.precheckOptionalBase64TextField(outerNode, "ciphertext", "outer.ciphertext");
        ParserSupport.precheckOptionalBase64TextField(outerNode, "tag", "outer.tag");
    }

    private static void precheckProtectedStructureAndSyntax(JsonNode protectedNode) {
        ParserSupport.precheckOptionalTextShape(protectedNode, "typ", "outer.protected.typ");
        ParserSupport.precheckOptionalTextShape(protectedNode, "cty", "outer.protected.cty");
        ParserSupport.precheckOptionalTextShape(protectedNode, "ver", "outer.protected.ver");
        ParserSupport.precheckOptionalTextShape(protectedNode, "wind_mode", "outer.protected.wind_mode");
        ParserSupport.precheckOptionalTextShape(protectedNode, "enc", "outer.protected.enc");
        ParserSupport.precheckOptionalTextShape(protectedNode, "key_alg", "outer.protected.key_alg");
        ParserSupport.precheckOptionalObjectShape(protectedNode, "kid", "outer.protected.kid");
        ParserSupport.precheckOptionalObjectShape(protectedNode, "epk", "outer.protected.epk");

        JsonNode kidNode = protectedNode.get("kid");
        if (kidNode != null) {
            ParserSupport.precheckOptionalTextShape(kidNode, "x25519", "outer.protected.kid.x25519");
            ParserSupport.precheckOptionalTextShape(kidNode, "mlkem768", "outer.protected.kid.mlkem768");
        }

        JsonNode epkNode = protectedNode.get("epk");
        if (epkNode != null) {
            ParserSupport.precheckOptionalTextShape(epkNode, "kty", "outer.protected.epk.kty");
            ParserSupport.precheckOptionalTextShape(epkNode, "crv", "outer.protected.epk.crv");
            ParserSupport.precheckOptionalTextShape(epkNode, "x", "outer.protected.epk.x");
        }
    }
}
