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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.order.Ordered;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.core.annotation.Order;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two OAuth 2.0 clients sharing the same JWKS URI must each fetch the key set under their own provider name,
 * because the name selects the service-specific HTTP client settings.
 */
class DefaultReactiveOpenIdTokenResponseValidatorSharedJwksUriTest {
    private static final String SPEC_NAME = "DefaultReactiveOpenIdTokenResponseValidatorSharedJwksUriTest";

    private static MockOpenIdProvider provider;
    private static EmbeddedServer server;

    @BeforeAll
    static void start() {
        provider = MockOpenIdProvider.start();
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "cookie",
            "micronaut.security.oauth2.clients.first.client-id", "first-client",
            "micronaut.security.oauth2.clients.first.client-secret", "not-a-real-secret",
            "micronaut.security.oauth2.clients.first.openid.issuer", provider.getIssuer(),
            "micronaut.security.oauth2.clients.second.client-id", "second-client",
            "micronaut.security.oauth2.clients.second.client-secret", "not-a-real-secret",
            "micronaut.security.oauth2.clients.second.openid.issuer", provider.getIssuer()));
    }

    @AfterAll
    static void stop() {
        server.close();
        provider.close();
    }

    @Test
    void eachClientFetchesTheSharedJwksUnderItsOwnProviderName() {
        RecordingJwkSetFetcher fetcher = server.getApplicationContext().getBean(RecordingJwkSetFetcher.class);
        fetcher.providerNames.clear();

        assertTrue(validate("first", "first-client").isPresent());
        assertTrue(validate("second", "second-client").isPresent());

        assertEquals(List.of("first", "second"), fetcher.providerNames);
    }

    @SuppressWarnings("unchecked")
    private static Optional<JWT> validate(String clientName, String clientId) {
        ApplicationContext context = server.getApplicationContext();
        ReactiveOpenIdTokenResponseValidator<JWT> validator = context.getBean(ReactiveOpenIdTokenResponseValidator.class);
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName(clientName));
        DefaultOpenIdProviderMetadata metadata = context.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName(clientName));
        OpenIdTokenResponse response = new OpenIdTokenResponse();
        response.setAccessToken("access-token");
        response.setTokenType("bearer");
        response.setIdToken(provider.signedJwt(claims -> claims.subject("sherlock").audience(clientId)));
        return Mono.from(validator.validate(clientConfiguration, metadata, response, null)).blockOptional();
    }

    @Singleton
    @Primary
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Replaces(DefaultJwkSetFetcher.class)
    @Requires(property = "spec.name", value = SPEC_NAME)
    static class RecordingJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        final List<String> providerNames = new CopyOnWriteArrayList<>();

        @Override
        @NonNull
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            providerNames.add(providerName);
            return Mono.just(provider.jwkSet());
        }

        @Override
        public void clearCache(String url) {
        }
    }
}
