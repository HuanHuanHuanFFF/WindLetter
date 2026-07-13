package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SenderEncryptionIdentityRefTest {

    @Test
    void shouldRequireNonBlankIdentityIdAndKeepOptionalSelector() {
        assertThrows(IllegalArgumentException.class, () -> new SenderEncryptionIdentityRef(" ", null));

        SenderEncryptionIdentityRef ref = new SenderEncryptionIdentityRef("sender", "current");
        assertEquals("sender", ref.identityId());
        assertEquals("current", ref.keySelector());
    }
}
