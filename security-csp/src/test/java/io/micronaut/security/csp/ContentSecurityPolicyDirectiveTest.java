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
package io.micronaut.security.csp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyDirectiveTest {

    @Test
    void headerValueIncludesDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'");

        assertEquals("default-src 'self'", directive.toHeaderValue());
    }

    @Test
    void headerValueOmitsMissingDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.UPGRADE_INSECURE_REQUESTS, null);

        assertEquals("upgrade-insecure-requests", directive.toHeaderValue());
    }

    @Test
    void valuesSplitsDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC,
                "'self'  https://api.example.com");

        assertEquals(List.of("'self'", "https://api.example.com"), directive.values());
    }

    @Test
    void blankValueHasNoTokensAndIsOmittedFromTheHeader() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SANDBOX, "   ");

        assertEquals(List.of(), directive.values());
        assertEquals("sandbox", directive.toHeaderValue());
        assertFalse(directive.isNone());
        assertFalse(directive.isSelf());
    }

    @Test
    void isNoneRecognizesOnlyTheQuotedKeyword() {
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, "'none'").isNone());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, "none").isNone());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, "'self'").isNone());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, null).isNone());
    }

    @Test
    void isSelfRecognizesOnlyTheQuotedKeyword() {
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'self'").isSelf());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "self").isSelf());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'none'").isSelf());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, null).isSelf());
    }

    @Test
    void toStringRedactsNonceSourcesButHeaderValueKeepsThem() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC,
            "'NONCE-abc123' 'self'  https://cdn.example.com");

        assertEquals("script-src 'NONCE-abc123' 'self'  https://cdn.example.com", directive.toHeaderValue());
        assertEquals("script-src 'nonce-[redacted]' 'self' https://cdn.example.com", directive.toString());
        assertEquals("sandbox", new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SANDBOX, null).toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"script-src; report-uri", "script src", "script-src,", ""})
    void rejectsANameThatIsNotADirectiveName(String name) {
        assertThrows(IllegalArgumentException.class, () -> new ContentSecurityPolicyDirective(name, "'self'"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"'self'; report-uri https://attacker.example", "'self'\r\nX-Injected: 1", "'self'\u0000"})
    void rejectsAValueThatWouldEndTheDirectiveOrTheHeader(String value) {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, value));

        assertTrue(exception.getMessage().contains("script-src"), exception::getMessage);
    }

    @Test
    void acceptsATabAndAComma() {
        assertEquals(List.of("'self'", "https://a.example.com,"),
            new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'self'\thttps://a.example.com,").values());
    }
}
