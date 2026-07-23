package com.windletter.protocol.codec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Base64UrlTest {

    @Test
    void allowEmptyDecoderReturnsEmptyPayload() {
        assertArrayEquals(new byte[0], Base64Url.decodeCanonicalAllowEmpty("", "payload.body.data"));
    }
}
