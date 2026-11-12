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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The JSON Web Key Set of an OpenID provider must only verify tokens issued by that provider. A key trusted for
 * provider beta must not be able to sign a token that carries the {@code iss} of provider alpha.
 */
class JwksSignatureBoundToIssuerTest {
    private static final String SPEC_NAME = "JwksSignatureBoundToIssuerTest";
    private static final String PROVIDER_SPEC_NAME = SPEC_NAME + ".provider";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final String ALPHA = "alpha";
    private static final String BETA = "beta";
    private static final Map<String, RSAKey> KEYS = new ConcurrentHashMap<>();

    private static EmbeddedServer alphaProvider;
    private static EmbeddedServer betaProvider;
    private static EmbeddedServer relyingParty;
    private static HttpClient httpClient;

    @BeforeAll
    static void start() {
        alphaProvider = startProvider(ALPHA);
        betaProvider = startProvider(BETA);
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.authentication", "idtoken");
        configuration.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        for (String provider : List.of(ALPHA, BETA)) {
            configuration.put("micronaut.security.oauth2.clients." + provider + ".client-id", clientId(provider));
            configuration.put("micronaut.security.oauth2.clients." + provider + ".client-secret", "test-fixture-not-a-secret");
            configuration.put("micronaut.security.oauth2.clients." + provider + ".openid.issuer", issuer(provider));
        }
        relyingParty = ApplicationContext.run(EmbeddedServer.class, configuration);
        httpClient = relyingParty.getApplicationContext().createBean(HttpClient.class, relyingParty.getURL());
    }

    @AfterAll
    static void stop() {
        httpClient.close();
        relyingParty.close();
        betaProvider.close();
        alphaProvider.close();
    }

    @Test
    void jwksSignatureConfigurationOfAnOpenIdClientIsBoundToTheClientIssuer() {
        for (String provider : List.of(ALPHA, BETA)) {
            JwksSignatureConfiguration configuration = relyingParty.getApplicationContext()
                .getBean(JwksSignatureConfiguration.class, Qualifiers.byName(provider));
            assertEquals(issuer(provider), configuration.getIssuer());
            assertEquals(issuer(provider) + "/keys", configuration.getUrl());
        }
    }

    @Test
    void tokensIssuedAndSignedByTheSameProviderAreAccepted() {
        BlockingHttpClient client = httpClient.toBlocking();
        for (String provider : List.of(ALPHA, BETA)) {
            String token = signedJwt(provider, claims -> claims.issuer(issuer(provider))
                .audience(clientId(provider))
                .subject("sherlock"));
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/username").accept(MediaType.TEXT_PLAIN).bearerAuth(token)));
        }
    }

    @Test
    void tokenSignedWithOneProviderKeyCannotCarryAnotherProviderIssuer() {
        BlockingHttpClient client = httpClient.toBlocking();
        String signedByBetaIssuedAsAlpha = signedJwt(BETA, claims -> claims.issuer(issuer(ALPHA))
            .audience(clientId(ALPHA))
            .subject("mallory"));
        assertUnauthorized(client, signedByBetaIssuedAsAlpha);

        String signedByAlphaIssuedAsBeta = signedJwt(ALPHA, claims -> claims.issuer(issuer(BETA))
            .audience(clientId(BETA))
            .subject("mallory"));
        assertUnauthorized(client, signedByAlphaIssuedAsBeta);
    }

    @Test
    void tokenWithoutIssuerIsRejected() {
        String token = signedJwt(ALPHA, claims -> claims.audience(clientId(ALPHA)).subject("mallory"));
        assertUnauthorized(httpClient.toBlocking(), token);
    }

    @Test
    void tokenWithEmptyOrSuffixIssuerIsRejected() {
        BlockingHttpClient client = httpClient.toBlocking();
        for (String provider : List.of(ALPHA, BETA)) {
            for (String iss : List.of("", "/", "https://", "com", "localhost", "default", ISSUER_PATH)) {
                String token = signedJwt(provider, claims -> claims.issuer(iss)
                    .audience(clientId(ALPHA))
                    .subject("mallory"));
                assertUnauthorized(client, token);
            }
        }
    }

    private static void assertUnauthorized(BlockingHttpClient client, String token) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/username").accept(MediaType.TEXT_PLAIN).bearerAuth(token)));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
    }

    private static EmbeddedServer startProvider(String name) {
        KEYS.computeIfAbsent(name, JwksSignatureBoundToIssuerTest::generateKey);
        return ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC_NAME, "mock.provider.name", name));
    }

    private static String issuer(String provider) {
        EmbeddedServer server = ALPHA.equals(provider) ? alphaProvider : betaProvider;
        return server.getURL() + ISSUER_PATH;
    }

    private static String clientId(String provider) {
        return provider + "-client";
    }

    private static String signedJwt(String provider, Consumer<JWTClaimsSet.Builder> customizer) {
        RSAKey key = KEYS.get(provider);
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)));
        customizer.accept(builder);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), builder.build());
        try {
            jwt.sign(new RSASSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;
        private final RSAKey key;

        ProviderController(HttpHostResolver httpHostResolver, @Property(name = "mock.provider.name") String name) {
            this.httpHostResolver = httpHostResolver;
            this.key = KEYS.get(name);
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            String issuer = httpHostResolver.resolve(request) + ISSUER_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/v1/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/v1/token\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        String keys() {
            return new JWKSet(key.toPublicJWK()).toString();
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    @Produces(MediaType.TEXT_PLAIN)
    static class UsernameController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/username")
        String username(Principal principal) {
            return principal.getName();
        }
    }
}
