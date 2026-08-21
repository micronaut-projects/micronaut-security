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
package io.micronaut.security.fetchmetadata.rules;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.server.cors.CorsOriginConfiguration;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrossOriginFetchMetadataRuleTest {

    @Test
    void matchesAnExplicitlyAllowedOrigin() {
        CorsOriginConfiguration configuration = new CorsOriginConfiguration();
        configuration.setAllowedOrigins(List.of("https://allowed.example"));

        assertTrue(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://allowed.example"));
        assertFalse(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://disallowed.example"));
    }

    @Test
    void matchesAnyOriginOnlyWhenNoRegexIsConfigured() {
        CorsOriginConfiguration configuration = new CorsOriginConfiguration();

        assertTrue(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://example.com"));

        configuration.setAllowedOriginsRegex("https://trusted\\.example");
        assertFalse(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://example.com"));
    }

    @Test
    void matchesAllowedOriginRegex() {
        CorsOriginConfiguration configuration = new CorsOriginConfiguration();
        configuration.setAllowedOrigins(List.of());
        configuration.setAllowedOriginsRegex("https://([a-z]+\\.)?example\\.com");

        assertTrue(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://api.example.com"));
        assertFalse(CrossOriginFetchMetadataRule.matchesOrigin(configuration,
            "https://example.org"));
    }

    @Test
    void matchesOnlyAllowedMethodsWhenMethodsAreRestricted() {
        CorsOriginConfiguration configuration = new CorsOriginConfiguration();

        assertTrue(CrossOriginFetchMetadataRule.matchesMethod(configuration, HttpMethod.POST));

        configuration.setAllowedMethods(List.of(HttpMethod.GET));
        assertTrue(CrossOriginFetchMetadataRule.matchesMethod(configuration, HttpMethod.GET));
        assertFalse(CrossOriginFetchMetadataRule.matchesMethod(configuration, HttpMethod.POST));
    }
}
