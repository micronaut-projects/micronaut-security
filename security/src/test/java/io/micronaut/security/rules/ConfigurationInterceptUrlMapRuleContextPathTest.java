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
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.security.config.DefaultInterceptUrlPatternModifier;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigurationInterceptUrlMapRuleContextPathTest {

    @ParameterizedTest(name = "pattern {0} with context path {1}: {2} {3} -> {4}")
    @MethodSource("rootPatterns")
    void rootPatternProtectsContextRoot(String pattern,
                                        @Nullable String contextPath,
                                        HttpMethod method,
                                        String requestPath,
                                        SecurityRuleResult expected) {
        ConfigurationInterceptUrlMapRule rule = rule(contextPath,
            new InterceptUrlMapPattern(pattern, List.of(SecurityRule.IS_AUTHENTICATED), null),
            new InterceptUrlMapPattern("/**", List.of(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(expected, check(rule, HttpRequest.create(method, requestPath)));
    }

    private static Stream<Arguments> rootPatterns() {
        return Stream.of(
            Arguments.of("/", null, HttpMethod.GET, "/", SecurityRuleResult.REJECTED),
            Arguments.of("/", null, HttpMethod.GET, "/other", SecurityRuleResult.ALLOWED),
            Arguments.of("/", "/portal", HttpMethod.GET, "/portal", SecurityRuleResult.REJECTED),
            Arguments.of("/", "/portal", HttpMethod.GET, "/portal/", SecurityRuleResult.REJECTED),
            Arguments.of("/", "/portal", HttpMethod.POST, "/portal", SecurityRuleResult.REJECTED),
            Arguments.of("/", "/portal", HttpMethod.GET, "/portal/other", SecurityRuleResult.ALLOWED),
            Arguments.of("/", "portal", HttpMethod.GET, "/portal", SecurityRuleResult.REJECTED),
            Arguments.of("/", "/portal/", HttpMethod.GET, "/portal/", SecurityRuleResult.REJECTED),
            Arguments.of("/", "/", HttpMethod.GET, "/", SecurityRuleResult.REJECTED),
            Arguments.of("/", "", HttpMethod.GET, "/", SecurityRuleResult.REJECTED),
            Arguments.of("/*", null, HttpMethod.GET, "/", SecurityRuleResult.REJECTED),
            Arguments.of("/*", null, HttpMethod.GET, "/other", SecurityRuleResult.REJECTED),
            Arguments.of("/*", null, HttpMethod.GET, "/other/nested", SecurityRuleResult.ALLOWED),
            Arguments.of("/*", "/portal", HttpMethod.GET, "/portal", SecurityRuleResult.REJECTED),
            Arguments.of("/*", "/portal", HttpMethod.GET, "/portal/", SecurityRuleResult.REJECTED),
            Arguments.of("/*", "/portal", HttpMethod.DELETE, "/portal", SecurityRuleResult.REJECTED),
            Arguments.of("/*", "/portal", HttpMethod.GET, "/portal/other", SecurityRuleResult.REJECTED),
            Arguments.of("/*", "/portal", HttpMethod.GET, "/portal/other/nested", SecurityRuleResult.ALLOWED),
            Arguments.of("/*", "portal", HttpMethod.GET, "/portal", SecurityRuleResult.REJECTED)
        );
    }


    @Test
    void contextRootHandlingDoesNotBroadenOtherPaths() {
        ConfigurationInterceptUrlMapRule rule = rule("/portal",
            new InterceptUrlMapPattern("/admin/*", List.of(SecurityRule.IS_ANONYMOUS), null),
            new InterceptUrlMapPattern("/**", List.of(SecurityRule.IS_AUTHENTICATED), null));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/portal/admin/users")));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.GET("/portal/admin")));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.GET("/portal")));
    }

    @Test
    void contextRootMatchingRequiresTheContextPath() {
        ConfigurationInterceptUrlMapRule rule = rule("/portal",
            new InterceptUrlMapPattern("/", List.of(SecurityRule.IS_AUTHENTICATED), null));

        assertTrue(rule.matchesPath("/portal/*", "/portal"));
        assertTrue(rule.matchesPath("/portal/", "/portal"));
        assertFalse(rule.matchesPath("/portal/*", "/"));
        assertFalse(rule.matchesPath("/portal/*", "/other"));
        assertFalse(rule.matchesPath("/other/*", "/portal"));
    }

    @Test
    void rulesWithoutContextPathProviderKeepMatchingPatterns() {
        SecurityConfigurationProperties securityConfiguration = new SecurityConfigurationProperties();
        securityConfiguration.setInterceptUrlMap(List.of(
            new InterceptUrlMapPattern("/", List.of(SecurityRule.IS_AUTHENTICATED), null),
            new InterceptUrlMapPattern("/**", List.of(SecurityRule.IS_ANONYMOUS), null)));
        ConfigurationInterceptUrlMapRule rule = new ConfigurationInterceptUrlMapRule(rolesFinder(), securityConfiguration,
            new DefaultInterceptUrlPatternModifier(securityConfiguration, () -> null), null);

        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.GET("/")));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/other")));
    }

    private static ConfigurationInterceptUrlMapRule rule(@Nullable String contextPath, InterceptUrlMapPattern... patterns) {
        SecurityConfigurationProperties securityConfiguration = new SecurityConfigurationProperties();
        securityConfiguration.setInterceptUrlMap(List.of(patterns));
        ServerContextPathProvider serverContextPathProvider = () -> contextPath;
        return new ConfigurationInterceptUrlMapRule(rolesFinder(),
            securityConfiguration,
            new DefaultInterceptUrlPatternModifier(securityConfiguration, serverContextPathProvider),
            serverContextPathProvider);
    }

    private static DefaultRolesFinder rolesFinder() {
        return new DefaultRolesFinder(new TokenConfiguration() { });
    }

    private static SecurityRuleResult check(SecurityRule<HttpRequest<?>> rule, HttpRequest<?> request) {
        return Mono.from(rule.check(request, null)).block();
    }
}
