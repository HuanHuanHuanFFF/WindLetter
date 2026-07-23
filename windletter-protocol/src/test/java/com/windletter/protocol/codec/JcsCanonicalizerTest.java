package com.windletter.protocol.codec;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JcsCanonicalizerTest {

    @Test
    void canonicalizesObjectKeysAndUtf8BytesIndependentlyOfInsertionOrder() {
        ObjectNode reverseInsertionOrder = JsonNodeFactory.instance.objectNode();
        reverseInsertionOrder.put("z", 1);
        reverseInsertionOrder.put("a", "\u00e9");

        ObjectNode forwardInsertionOrder = JsonNodeFactory.instance.objectNode();
        forwardInsertionOrder.put("a", "\u00e9");
        forwardInsertionOrder.put("z", 1);

        byte[] canonical = JcsCanonicalizer.canonicalize(reverseInsertionOrder);

        assertArrayEquals("{\"a\":\"é\",\"z\":1}".getBytes(StandardCharsets.UTF_8), canonical);
        assertEquals("7b2261223a22c3a9222c227a223a317d", HexFormat.of().formatHex(canonical));
        assertArrayEquals(canonical, JcsCanonicalizer.canonicalize(forwardInsertionOrder));
    }

    @Test
    void preservesArrayOrder() {
        ArrayNode first = JsonNodeFactory.instance.arrayNode().add(1).add(2);
        ArrayNode reversed = JsonNodeFactory.instance.arrayNode().add(2).add(1);

        assertNotEquals(
                new String(JcsCanonicalizer.canonicalize(first), StandardCharsets.UTF_8),
                new String(JcsCanonicalizer.canonicalize(reversed), StandardCharsets.UTF_8)
        );
    }

    @Test
    void rejectsNullInput() {
        assertThrows(IllegalArgumentException.class, () -> JcsCanonicalizer.canonicalize(null));
    }
}
