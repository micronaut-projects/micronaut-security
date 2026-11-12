/*
 * Copyright 2026 original authors
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
package io.micronaut.security.rules;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InterceptUrlMapRulePathForMatchingTest {

    @ParameterizedTest(name = "{0} is matched as {1}")
    @CsvSource(delimiter = '|', value = {
        "/admin/1                 | /admin/1",
        "/admin/x%2Fy             | /admin/x%2Fy",
        "/admin/x%2fy             | /admin/x%2fy",
        "/admin/%2E%2E%2Fx        | /admin/%2E%2E%2Fx",
        "/admin/%20               | /admin/%20",
        "/admin/%09               | /admin/%09",
        "/admin/%00               | /admin/%00",
        "/admin/%20%09            | /admin/%20%09",
        "/admin/%20x              | /admin/ x",
        "/admin/jos%C3%A9         | /admin/josé",
        "/admin/a%2Bb             | /admin/a+b",
        "/admin/a+b               | /admin/a+b",
        "/users/x%2Fy/roles       | /users/x%2Fy/roles",
        "/users/jos%C3%A9/roles/  | /users/josé/roles/",
        "/%20/admin/settings      | /%20/admin/settings",
        "/                        | /",
        "''                       | ''"
    })
    void pathForMatching(String rawPath, String expected) {
        assertEquals(expected, InterceptUrlMapRule.pathForMatching(HttpRequest.GET(rawPath)));
    }

    @ParameterizedTest(name = "GET {0} -> {1}")
    @MethodSource("requests")
    void fixedDepthPatternsApplyToEncodedPathVariables(String rawPath, SecurityRuleResult expected) {
        SecurityRule<HttpRequest<?>> rule = new InterceptUrlMapRule(new DefaultRolesFinder(new TokenConfiguration() { })) {
            @Override
            protected List<InterceptUrlMapPattern> getPatternList() {
                return List.of(
                    new InterceptUrlMapPattern("/admin/*", List.of("ROLE_ADMIN"), HttpMethod.GET),
                    new InterceptUrlMapPattern("/users/*/roles", List.of("ROLE_ADMIN"), null),
                    new InterceptUrlMapPattern("/books/café", List.of("ROLE_ADMIN"), null),
                    new InterceptUrlMapPattern("/**", List.of(SecurityRule.IS_ANONYMOUS), null));
            }
        };
        Authentication user = Authentication.build("john", List.of("ROLE_USER"));
        assertEquals(expected, Mono.from(rule.check(HttpRequest.GET(rawPath), user)).block());
    }

    private static Stream<Arguments> requests() {
        return Stream.of(
            Arguments.of("/admin/1", SecurityRuleResult.REJECTED),
            Arguments.of("/admin/x%2Fy", SecurityRuleResult.REJECTED),
            Arguments.of("/admin/%20", SecurityRuleResult.REJECTED),
            Arguments.of("/admin/%00", SecurityRuleResult.REJECTED),
            Arguments.of("/admin/x/y", SecurityRuleResult.ALLOWED),
            Arguments.of("/users/x%2Fy/roles", SecurityRuleResult.REJECTED),
            Arguments.of("/users/%09/roles", SecurityRuleResult.REJECTED),
            Arguments.of("/users/x/y/roles", SecurityRuleResult.ALLOWED),
            Arguments.of("/books/caf%C3%A9", SecurityRuleResult.REJECTED),
            Arguments.of("/books/other", SecurityRuleResult.ALLOWED)
        );
    }
}
