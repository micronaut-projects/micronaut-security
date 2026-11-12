package io.micronaut.security.html;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(startApplication = false)
class HtmlSanitizerConfigurationTest {

    @Test
    void testHtmlSanitizerConfigurationEnabledByDefault(HtmlSanitizerConfiguration htmlSanitizerConfiguration) {
        assertTrue(htmlSanitizerConfiguration.isEnabled());
    }

    @Test
    void testHtmlSanitizerConfigurationDefaultPolicies(HtmlSanitizerConfiguration htmlSanitizerConfiguration) {
        assertEquals(List.of(
            HtmlSanitizerPolicy.BLOCKS,
            HtmlSanitizerPolicy.FORMATTING,
            HtmlSanitizerPolicy.LINKS
        ), htmlSanitizerConfiguration.getPolicies());
    }
}
