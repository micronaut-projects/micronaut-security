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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The ID token returned by the token endpoint must be verified with the issuing provider's JSON Web Key Set only.
 */
class DefaultReactiveOpenIdTokenResponseValidatorTest {
    private static final String CLIENT_ID = "relying-party";
    private static final String SECRET = "pleaseChangeThisSecretForANewOne";

    private static MockOpenIdProvider provider;
    private static EmbeddedServer server;

    @BeforeAll
    static void start() {
        provider = MockOpenIdProvider.start();
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", "DefaultReactiveOpenIdTokenResponseValidatorTest",
            "micronaut.security.authentication", "cookie",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", SECRET,
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
    void idTokenSignedByTheProviderIsValid() throws ParseException {
        Optional<JWT> jwt = validate(provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID)));
        assertTrue(jwt.isPresent());
        assertEquals("sherlock", jwt.get().getJWTClaimsSet().getSubject());
    }

    @Test
    void genericClaimsValidatorsReceiveTheCurrentRequest() {
        RequestRecorder recorder = server.getApplicationContext().getBean(RequestRecorder.class);
        recorder.requests.clear();
        HttpRequest<?> request = HttpRequest.GET("/oauth/callback/auth");
        Optional<JWT> jwt = ServerRequestContext.with(request, (Supplier<Optional<JWT>>) () ->
            validate(provider.signedJwt(claims -> claims.subject("sherlock").audience(CLIENT_ID))));
        assertTrue(jwt.isPresent());
        assertTrue(recorder.requests.stream().anyMatch(r -> r == request));
        assertSame(request, recorder.requests.getLast());
    }

    @Test
    void idTokenSignedWithAKeyTheProviderDoesNotPublishIsRejected() {
        assertTrue(validate(provider.signedJwtWithUnknownKey(claims -> claims.subject("sherlock").audience(CLIENT_ID))).isEmpty());
    }

    @Test
    void idTokenSignedWithTheApplicationSecretIsRejected() throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims().build());
        jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
        assertTrue(validate(jwt.serialize()).isEmpty());
    }

    @Test
    void unsignedIdTokenIsRejected() {
        assertTrue(validate(new PlainJWT(new PlainHeader(), claims().build()).serialize()).isEmpty());
    }

    @Test
    void idTokenIssuedToAnotherClientIsRejected() {
        assertTrue(validate(provider.signedJwt(claims -> claims.subject("sherlock").audience("other-client"))).isEmpty());
    }

    @Test
    void malformedIdTokenIsRejected() {
        assertTrue(validate("not-a-jwt").isEmpty());
    }

    private static JWTClaimsSet.Builder claims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
            .issuer(provider.getIssuer())
            .subject("sherlock")
            .audience(CLIENT_ID)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)));
    }

    @SuppressWarnings("unchecked")
    private static Optional<JWT> validate(String idToken) {
        ApplicationContext context = server.getApplicationContext();
        ReactiveOpenIdTokenResponseValidator<JWT> validator = context.getBean(ReactiveOpenIdTokenResponseValidator.class);
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName("auth"));
        DefaultOpenIdProviderMetadata metadata = context.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName("auth"));
        OpenIdTokenResponse response = new OpenIdTokenResponse();
        response.setAccessToken("access-token");
        response.setTokenType("bearer");
        response.setIdToken(idToken);
        return Mono.from(validator.validate(clientConfiguration, metadata, response, null)).blockOptional();
    }

    @Singleton
    @Requires(property = "spec.name", value = "DefaultReactiveOpenIdTokenResponseValidatorTest")
    static class RequestRecorder implements GenericJwtClaimsValidator<HttpRequest<?>> {
        final List<HttpRequest<?>> requests = new CopyOnWriteArrayList<>();

        @Override
        public boolean validate(Claims claims, HttpRequest<?> request) {
            requests.add(request);
            return true;
        }
    }
}
