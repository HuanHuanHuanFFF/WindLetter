package com.windletter.testkit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Placeholder self-check tests.
 * 自检占位测试。
 */
public class SelfCheckTests {
    @Test
    void selfCheckPasses() {
        SelfCheckReport report = WindLetterSelfCheck.run();
        assertNotNull(report);
        assertTrue(report.isAllPassed(), report.getDetails());
    }
}
