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
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The OAuth 2.0 login response carries per-request values and must not be cached.
 */
class OauthLoginCacheControlTest {

    private static final String SPEC_NAME = "OauthLoginCacheControlTest";

    @Test
    void loginRedirectIsNotStored() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, CollectionUtils.mapOf(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false,
            "micronaut.security.oauth2.clients.auth.authorization.url", "https://provider.example/authorize",
            "micronaut.security.oauth2.clients.auth.token.url", "https://provider.example/token",
            "micronaut.security.oauth2.clients.auth.client-id", "client-id-fixture",
            "micronaut.security.oauth2.clients.auth.client-secret", "client-secret-fixture-not-a-secret"))) {

            HttpResponse<?> response = exchange(server, "/oauth/login/auth");

            assertEquals(HttpStatus.FOUND, response.status());
            assertNotNull(response.getHeaders().get(HttpHeaders.LOCATION));
            assertEquals("no-store", response.getHeaders().get(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void cacheControlChosenByTheClientIsKept() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME + "CustomClient",
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false))) {

            HttpResponse<?> response = exchange(server, "/oauth/login/custom");

            assertEquals(HttpStatus.FOUND, response.status());
            assertEquals("private, max-age=0", response.getHeaders().get(HttpHeaders.CACHE_CONTROL));
        }
    }

    private static HttpResponse<?> exchange(EmbeddedServer server, String path) {
        try (HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            return client.toBlocking().exchange(HttpRequest.GET(path));
        }
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

    @Requires(property = "spec.name", value = SPEC_NAME + "CustomClient")
    @Singleton
    @Named("custom")
    static class CustomOauthClient implements OauthClient {
        @Override
        public String getName() {
            return "custom";
        }

        @Override
        public Publisher<MutableHttpResponse<?>> authorizationRedirect(HttpRequest<?> originating) {
            return Mono.just(HttpResponse.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, "https://provider.example/authorize")
                .header(HttpHeaders.CACHE_CONTROL, "private, max-age=0"));
        }

        @Override
        public Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request) {
            return Mono.empty();
        }
    }
}
