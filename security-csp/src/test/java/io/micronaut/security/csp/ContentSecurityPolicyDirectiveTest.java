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

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyDirectiveTest {

    @Test
    void toStringIncludesDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'");

        assertEquals("default-src 'self'", directive.toString());
    }

    @Test
    void toStringOmitsMissingDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null);

        assertEquals("upgrade-insecure-requests", directive.toString());
    }

    @Test
    void valuesSplitsDirectiveValue() {
        ContentSecurityPolicyDirective directive = new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC,
                "'self'  https://api.example.com");

        assertEquals(List.of("'self'", "https://api.example.com"), directive.values());
    }

    @Test
    void isNoneRecognizesQuotedAndUnquotedNoneValues() {
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'none'").isNone());
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "none").isNone());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'self'").isNone());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, null).isNone());
    }

    @Test
    void isSelfRecognizesQuotedAndUnquotedSelfValues() {
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'self'").isSelf());
        assertTrue(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "self").isSelf());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'").isSelf());
        assertFalse(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, null).isSelf());
    }
}
