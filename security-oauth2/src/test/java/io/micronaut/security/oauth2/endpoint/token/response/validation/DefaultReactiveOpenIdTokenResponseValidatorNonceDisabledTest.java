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

import com.nimbusds.jwt.JWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With the nonce claim validator disabled, the ID token is accepted whatever its {@code nonce} claim and the persisted
 * nonce, both in the authorization code flow and in flows without an authorization request.
 */
class DefaultReactiveOpenIdTokenResponseValidatorNonceDisabledTest {
    private static final String CLIENT_ID = "relying-party";

    private static MockOpenIdProvider provider;
    private static EmbeddedServer server;

    @BeforeAll
    static void start() {
        provider = MockOpenIdProvider.start();
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "micronaut.security.authentication", "cookie",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne",
            "micronaut.security.token.jwt.claims-validators.nonce", false,
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
    void idTokenWhoseNonceClaimDoesNotMatchThePersistedNonceIsAccepted() {
        assertFalse(server.getApplicationContext().containsBean(NonceClaimValidator.class));

        assertTrue(validate(idTokenWithNonce("nonce-in-the-id-token"),
            (validator, args) -> validator.validate(args.clientConfiguration(), args.metadata(), args.response(), "persisted-nonce")));
    }

    @Test
    void idTokenWithoutNonceClaimIsAcceptedWhenNoNonceWasPersisted() {
        assertTrue(validate(provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID)),
            (validator, args) -> validator.validate(args.clientConfiguration(), args.metadata(), args.response(), null)));
    }

    @Test
    void idTokenWithANonceClaimIsAcceptedInAFlowWithoutAuthorizationRequest() {
        assertTrue(validate(idTokenWithNonce("unsolicited"),
            (validator, args) -> validator.validateWithoutNonce(args.clientConfiguration(), args.metadata(), args.response())));
    }

    private static String idTokenWithNonce(String nonce) {
        return provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID).claim("nonce", nonce));
    }

    @SuppressWarnings("unchecked")
    private static boolean validate(String idToken,
                                    BiFunction<ReactiveOpenIdTokenResponseValidator<JWT>, ValidationArguments, Publisher<JWT>> validation) {
        ApplicationContext context = server.getApplicationContext();
        OpenIdTokenResponse response = new OpenIdTokenResponse();
        response.setAccessToken("access-token");
        response.setTokenType("bearer");
        response.setIdToken(idToken);
        ValidationArguments args = new ValidationArguments(
            context.getBean(OauthClientConfiguration.class, Qualifiers.byName("auth")),
            context.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName("auth")),
            response);
        return Mono.from(validation.apply(context.getBean(ReactiveOpenIdTokenResponseValidator.class), args)).blockOptional().isPresent();
    }

    private record ValidationArguments(OauthClientConfiguration clientConfiguration,
                                       DefaultOpenIdProviderMetadata metadata,
                                       OpenIdTokenResponse response) {
    }
}
