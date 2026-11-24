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
package io.micronaut.security.oauth2.routes;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.AnnotationMetadata;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpMethod;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.web.router.Router;
import io.micronaut.web.router.UriRouteMatch;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The login route carries the Fetch Metadata marker annotation wherever it is registered, even though Micronaut Security
 * Fetch Metadata is not on this module's runtime classpath.
 */
class OauthLoginRouteDenyCrossSiteNavigationTest {

    private static final String SPEC_NAME = "OauthLoginRouteDenyCrossSiteNavigationTest";
    private static final String ANNOTATION = "io.micronaut.security.fetchmetadata.DenyCrossSiteNavigation";

    @Test
    void fetchMetadataIsNotOnTheRuntimeClasspath() {
        assertThrows(ClassNotFoundException.class, () -> Class.forName(ANNOTATION));
    }

    @Test
    void providerAndDefaultProviderLoginRoutesAreAnnotated() {
        try (ApplicationContext context = ApplicationContext.run(configuration(Map.of(
            "micronaut.security.oauth2.default-provider", "auth")))) {
            assertTrue(route(context, HttpMethod.GET, "/oauth/login/auth").hasAnnotation(ANNOTATION));
            assertTrue(route(context, HttpMethod.GET, "/oauth/login").hasAnnotation(ANNOTATION));
        }
    }

    @Test
    void loginRouteAtACustomUriIsAnnotated() {
        try (ApplicationContext context = ApplicationContext.run(configuration(Map.of(
            "micronaut.security.oauth2.login-uri", "/sign-in{/provider}")))) {
            assertTrue(route(context, HttpMethod.GET, "/sign-in/auth").hasAnnotation(ANNOTATION));
        }
    }

    @Test
    void callbackRouteIsNotAnnotated() {
        try (ApplicationContext context = ApplicationContext.run(configuration(Map.of()))) {
            assertFalse(route(context, HttpMethod.GET, "/oauth/callback/auth").hasAnnotation(ANNOTATION));
            assertFalse(route(context, HttpMethod.POST, "/oauth/callback/auth").hasAnnotation(ANNOTATION));
        }
    }

    private static Map<String, Object> configuration(Map<String, Object> overrides) {
        Map<String, Object> configuration = new HashMap<>(CollectionUtils.mapOf(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "cookie",
            "micronaut.security.oauth2.clients.auth.authorization.url", "https://provider.example/authorize",
            "micronaut.security.oauth2.clients.auth.token.url", "https://provider.example/token",
            "micronaut.security.oauth2.clients.auth.client-id", "client-id-fixture",
            "micronaut.security.oauth2.clients.auth.client-secret", "client-secret-fixture-not-a-secret"));
        configuration.putAll(overrides);
        return configuration;
    }

    private static AnnotationMetadata route(ApplicationContext context, HttpMethod method, String path) {
        UriRouteMatch<Object, Object> match = context.getBean(Router.class).<Object, Object>route(method, path)
            .orElseThrow(() -> new AssertionError("no route for " + method + " " + path));
        return match.getAnnotationMetadata();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    @Named("auth")
    static class AuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("user"));
        }
    }
}
