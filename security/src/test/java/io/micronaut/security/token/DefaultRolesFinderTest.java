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
package io.micronaut.security.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import io.micronaut.security.token.config.TokenConfiguration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DefaultRolesFinderTest {

    private static final String ROLES = "roles";

    private static DefaultRolesFinder rolesFinder(String separator) {
        return new DefaultRolesFinder(new TokenConfiguration() {
            @Override
            public String getRolesSeparator() {
                return separator;
            }
        });
    }

    static Stream<Arguments> literalSeparators() {
        return Stream.of(
                // regular expression metacharacters are matched literally
                arguments("|", "ADMIN|USER", List.of("ADMIN", "USER")),
                arguments(".", "a.b", List.of("a", "b")),
                arguments("+", "a+b", List.of("a", "b")),
                arguments("(", "a(b", List.of("a", "b")),
                arguments("\\s+", "ADMIN\\s+USER", List.of("ADMIN", "USER")),
                // a pattern is not interpreted, so it does not split the value
                arguments("\\s+", "ADMIN USER", List.of("ADMIN USER")),
                arguments(",\\s*", "ADMIN, USER", List.of("ADMIN, USER")),
                // roles are trimmed
                arguments(",", "ADMIN, USER", List.of("ADMIN", "USER")),
                arguments(",", " ADMIN\t,\nUSER ", List.of("ADMIN", "USER")),
                // empty entries are dropped
                arguments(",", "ADMIN,,USER", List.of("ADMIN", "USER")),
                arguments(",", ",ADMIN,USER,", List.of("ADMIN", "USER")),
                arguments(",", "ADMIN, ,USER", List.of("ADMIN", "USER")),
                arguments(" ", "read  write", List.of("read", "write")),
                arguments(",", "", List.of()),
                arguments(",", "  ", List.of()),
                arguments(",", ",,", List.of()),
                // separators longer than a character
                arguments(", ", "ADMIN, USER", List.of("ADMIN", "USER")),
                arguments("::", "ADMIN::USER:VIEWER", List.of("ADMIN", "USER:VIEWER")),
                arguments("aa", "XaaaY", List.of("X", "aY")),
                // a value without the separator is a single role
                arguments(",", "ADMIN", List.of("ADMIN")));
    }

    @ParameterizedTest(name = "[{index}] separator \"{0}\" splits \"{1}\" into {2}")
    @MethodSource("literalSeparators")
    void stringClaimIsSplitOnTheLiteralSeparator(String separator, String value, List<String> expected) {
        assertEquals(expected, rolesFinder(separator).resolveRoles(Map.of(ROLES, value)));
    }

    @Test
    void charSequenceClaimIsSplit() {
        assertEquals(List.of("ADMIN", "USER"),
                rolesFinder(",").resolveRoles(Map.of(ROLES, new StringBuilder("ADMIN, USER"))));
    }

    @Test
    void stringClaimIsNotSplitWhenNoSeparatorIsConfigured() {
        assertEquals(List.of("ADMIN,USER"), rolesFinder(null).resolveRoles(Map.of(ROLES, "ADMIN,USER")));
    }

    @Test
    void stringClaimIsNotSplitWhenTheSeparatorIsEmpty() {
        assertEquals(List.of("ADMIN,USER"), rolesFinder("").resolveRoles(Map.of(ROLES, "ADMIN,USER")));
    }

    @Test
    void collectionClaimIsNotModifiedByTheSeparator() {
        assertEquals(List.of("ADMIN, USER", " VIEWER"),
                rolesFinder(",").resolveRoles(Map.of(ROLES, List.of("ADMIN, USER", " VIEWER"))));
    }

    @Test
    void claimOfAnotherTypeResolvesToItsStringRepresentation() {
        assertEquals(List.of("42"), rolesFinder(",").resolveRoles(Map.of(ROLES, 42)));
    }

    @Test
    void missingClaimResolvesToNoRoles() {
        assertEquals(List.of(), rolesFinder(",").resolveRoles(Map.of("sub", "john")));
    }

    @Test
    void nullAttributesResolveToNoRoles() {
        assertEquals(List.of(), rolesFinder(",").resolveRoles(null));
    }
}
