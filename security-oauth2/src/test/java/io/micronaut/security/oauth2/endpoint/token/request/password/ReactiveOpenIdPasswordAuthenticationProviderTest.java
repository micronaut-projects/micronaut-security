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
package io.micronaut.security.oauth2.endpoint.token.request.password;

import com.nimbusds.jwt.JWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.NonceFactory;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The password grant has no authorization request, so no nonce is ever sent or persisted. The ID token must be
 * accepted even though nonce support is enabled for the authorization code flow.
 */
class ReactiveOpenIdPasswordAuthenticationProviderTest {
    private static final String CLIENT_ID = "relying-party";

    private static MockOpenIdProvider provider;
    private static EmbeddedServer server;

    @BeforeAll
    static void start() {
        provider = MockOpenIdProvider.start();
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "micronaut.security.authentication", "cookie",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne",
            "micronaut.security.oauth2.clients.auth.client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients.auth.client-secret", "not-a-real-secret",
            "micronaut.security.oauth2.clients.auth.openid.issuer", provider.getIssuer()));
    }

    @AfterAll
    static void stop() {
        server.close();
        provider.close();
    }

    @Test
    void idTokenWithoutNonceClaimAuthenticatesTheUserEvenIfNonceSupportIsEnabled() {
        assertTrue(server.getApplicationContext().containsBean(NonceFactory.class));

        List<AuthenticationResponse> responses = authenticate(
            provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID)));

        assertEquals(1, responses.size());
        assertTrue(responses.getFirst().isAuthenticated());
        assertEquals("sherlock", responses.getFirst().getAuthentication().orElseThrow().getName());
    }

    @Test
    void idTokenWithANonceClaimIsRejectedBecauseNoNonceWasSent() {
        List<AuthenticationResponse> responses = authenticate(
            provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID).claim("nonce", "unsolicited")));

        assertTrue(responses.isEmpty());
    }

    @SuppressWarnings("unchecked")
    private static List<AuthenticationResponse> authenticate(String idToken) {
        ApplicationContext context = server.getApplicationContext();
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse();
        tokenResponse.setAccessToken("access-token");
        tokenResponse.setTokenType("bearer");
        tokenResponse.setIdToken(idToken);
        ReactiveOpenIdPasswordAuthenticationProvider<Object, String, String> authenticationProvider =
            new ReactiveOpenIdPasswordAuthenticationProvider<>(
                context.getBean(OauthClientConfiguration.class, Qualifiers.byName("auth")),
                context.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName("auth")),
                new FixedTokenEndpointClient(tokenResponse),
                context.getBean(DefaultOpenIdAuthenticationMapper.class),
                (ReactiveOpenIdTokenResponseValidator<JWT>) context.getBean(ReactiveOpenIdTokenResponseValidator.class));
        return Flux.from(authenticationProvider.authenticate(null, new UsernamePasswordCredentials("sherlock", "password")))
            .collectList()
            .block();
    }

    private record FixedTokenEndpointClient(TokenResponse tokenResponse) implements TokenEndpointClient {
        @Override
        @SuppressWarnings("unchecked")
        public <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext) {
            return Mono.just((R) tokenResponse);
        }
    }
}
