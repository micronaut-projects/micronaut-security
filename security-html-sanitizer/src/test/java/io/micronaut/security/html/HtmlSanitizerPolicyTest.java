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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertSame;

class HtmlSanitizerPolicyTest {

    @ParameterizedTest
    @MethodSource("policies")
    void policyFactoryReturnsOwaspPolicyFactory(HtmlSanitizerPolicy policy, PolicyFactory expectedPolicyFactory) {
        assertSame(expectedPolicyFactory, policy.policyFactory());
    }

    private static Stream<Arguments> policies() {
        return Stream.of(
            Arguments.of(HtmlSanitizerPolicy.BLOCKS, Sanitizers.BLOCKS),
            Arguments.of(HtmlSanitizerPolicy.FORMATTING, Sanitizers.FORMATTING),
            Arguments.of(HtmlSanitizerPolicy.LINKS, Sanitizers.LINKS),
            Arguments.of(HtmlSanitizerPolicy.TABLES, Sanitizers.TABLES),
            Arguments.of(HtmlSanitizerPolicy.IMAGES, Sanitizers.IMAGES),
            Arguments.of(HtmlSanitizerPolicy.STYLES, Sanitizers.STYLES)
        );
    }
}
