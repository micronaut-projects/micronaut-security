/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.html;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.util.HtmlEntityEncodingHtmlSanitizer;
import io.micronaut.http.util.HtmlSanitizer;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OwaspHtmlSanitizerTest {

    @Test
    void suppliesOwaspHtmlSanitizerByDefault() {
        try (ApplicationContext context = ApplicationContext.run()) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);

            assertInstanceOf(OwaspHtmlSanitizer.class, sanitizer);
            assertFalse(context.containsBean(HtmlEntityEncodingHtmlSanitizer.class));
        }
    }

    @Test
    void sanitizerCanBeDisabled() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(HtmlSanitizerConfigurationProperties.PREFIX + ".enabled", false))) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);

            assertInstanceOf(HtmlEntityEncodingHtmlSanitizer.class, sanitizer);
            assertFalse(context.containsBean(OwaspHtmlSanitizer.class));
        }
    }

    @Test
    void preservesCoreNullAndEmptyBehavior() {
        try (ApplicationContext context = ApplicationContext.run()) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);

            assertEquals("", sanitizer.sanitize(null));
            assertEquals("", sanitizer.sanitize(""));
        }
    }

    @Test
    void allowsSafeBlockFormattingAndLinkMarkupByDefault() {
        try (ApplicationContext context = ApplicationContext.run()) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);
            String sanitized = sanitizer.sanitize("<p>Hello <strong>world</strong> <a href=\"https://example.com\">link</a></p>");

            assertTrue(sanitized.contains("<p>"));
            assertTrue(sanitized.contains("<strong>world</strong>"));
            assertTrue(sanitized.contains("<a href=\"https://example.com\""));
            assertTrue(sanitized.contains(">link</a>"));
        }
    }

    @Test
    void removesDangerousMarkupAndUrlsByDefault() {
        try (ApplicationContext context = ApplicationContext.run()) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);
            String sanitized = sanitizer.sanitize("""
                <p onclick="alert(1)">safe<script>alert(1)</script>
                <a href="javascript:alert(1)">bad</a>
                <img src="https://example.com/a.png" onerror="alert(1)">
                <table><tr><td>cell</td></tr></table>
                <span style="color:red">red</span></p>
                """);

            assertFalse(sanitized.contains("<script"));
            assertFalse(sanitized.contains("onclick"));
            assertFalse(sanitized.contains("javascript:"));
            assertFalse(sanitized.contains("<img"));
            assertFalse(sanitized.contains("<table"));
            assertFalse(sanitized.contains("style="));
            assertTrue(sanitized.contains("safe"));
            assertTrue(sanitized.contains("bad"));
            assertTrue(sanitized.contains("cell"));
            assertTrue(sanitized.contains("red"));
        }
    }

    @Test
    void configuredPolicyListChangesAllowedMarkup() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            HtmlSanitizerConfigurationProperties.PREFIX + ".policies", "BLOCKS,FORMATTING,LINKS,IMAGES"
        ))) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);
            String sanitized = sanitizer.sanitize("<p><img src=\"https://example.com/a.png\" alt=\"A\"></p>");

            assertTrue(sanitized.contains("<img"));
            assertTrue(sanitized.contains("src=\"https://example.com/a.png\""));
        }
    }

    @Test
    void configurationPoliciesCannotBeMutatedThroughGetter() {
        try (ApplicationContext context = ApplicationContext.run()) {
            HtmlSanitizerConfiguration configuration = context.getBean(HtmlSanitizerConfiguration.class);
            List<HtmlSanitizerPolicy> policies = configuration.getPolicies();

            assertThrows(UnsupportedOperationException.class, () -> policies.add(HtmlSanitizerPolicy.IMAGES));
        }
    }

    @Test
    void namedPolicyFactoryCustomizesSanitizerPolicy() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("micronaut.security.html-sanitizer.policies[0]", "FORMATTING"))) {
            HtmlSanitizer sanitizer = context.getBean(HtmlSanitizer.class);
            String sanitized = sanitizer.sanitize("<p><strong>safe</strong> <a href=\"https://example.com\">link</a></p>");

            assertTrue(sanitized.contains("<strong>safe</strong>"));
            assertFalse(sanitized.contains("<p>"));
            assertFalse(sanitized.contains("<a "));
            assertTrue(sanitized.contains("link"));
        }
    }
}
