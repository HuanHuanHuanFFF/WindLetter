package com.windletter.protocol.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Factory for protocol-layer JSON mappers with strict parser policy.
 */
public final class ProtocolJsonMapperFactory {

    private ProtocolJsonMapperFactory() {
    }

    /**
     * Create a strict parser mapper from default Jackson settings.
     */
    public static ObjectMapper strictParserMapper() {
        return applyStrictParserPolicy(new ObjectMapper());
    }

    /**
     * Create a strict parser mapper from a caller-provided mapper template.
     * <p>
     * The input mapper is not modified.
     */
    public static ObjectMapper strictParserMapper(ObjectMapper mapper) {
        if (mapper == null) {
            throw new IllegalArgumentException("mapper must not be null");
        }
        return applyStrictParserPolicy(mapper.copy());
    }

    private static ObjectMapper applyStrictParserPolicy(ObjectMapper mapper) {
        mapper.getFactory().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

        mapper.getFactory().disable(JsonReadFeature.ALLOW_SINGLE_QUOTES.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_JAVA_COMMENTS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_YAML_COMMENTS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_LEADING_ZEROS_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_TRAILING_DECIMAL_POINT_FOR_NUMBERS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS.mappedFeature());
        mapper.getFactory().disable(JsonReadFeature.ALLOW_MISSING_VALUES.mappedFeature());
        return mapper;
    }
}
