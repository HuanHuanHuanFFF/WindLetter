package com.windletter.testkit.demo;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WindLetterDemoTest {

    @Test
    void runsSuccessAndSafeFailureScenariosWithoutJUnitAsRuntime() {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        WindLetterDemo.run(new PrintStream(bytes, true, StandardCharsets.UTF_8));
        String output = bytes.toString(StandardCharsets.UTF_8);

        assertTrue(output.contains("auth=UNSIGNED"));
        assertTrue(output.contains("auth=SIGNED_VALID"));
        assertTrue(output.contains("NOT_FOR_ME status=NOT_FOR_ME error=NOT_FOR_ME"));
        assertTrue(output.contains(
            "INVALID_MESSAGE status=INVALID_MESSAGE error=INVALID_MESSAGE keyLeases=0"
        ));
        assertTrue(output.contains("DEMO_OK successes=4"));
    }
}
