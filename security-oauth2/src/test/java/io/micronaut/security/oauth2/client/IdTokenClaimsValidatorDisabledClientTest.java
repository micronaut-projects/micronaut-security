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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.MapClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * In {@code idtoken} authentication mode, ID tokens issued to an OAuth 2.0 client configured with
 * {@code micronaut.security.oauth2.clients.*.enabled: false} must not authenticate requests.
 */
class IdTokenClaimsValidatorDisabledClientTest {
    private static final String SPEC_NAME = "IdTokenClaimsValidatorDisabledClientTest";
    private static final String PROVIDER_SPEC_NAME = "IdTokenClaimsValidatorDisabledClientTestProvider";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final String CLIENT_ID = "relying-party";
    private static final String SIBLING_CLIENT_ID = "active-party";
    private static final RSAKey PROVIDER_KEY = generateKey("disabled-client-test-provider-key");

    private static EmbeddedServer provider;

    @BeforeAll
    static void startProvider() {
        provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC_NAME));
    }

    @AfterAll
    static void stopProvider() {
        if (provider != null) {
            provider.close();
        }
    }

    @Test
    void idTokensIssuedToDisabledClientAreRejected() {
        try (EmbeddedServer server = startRelyingParty(false);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertFalse(server.getApplicationContext().containsBean(OpenIdClient.class),
                "a disabled client must not register login routes");
            BlockingHttpClient client = httpClient.toBlocking();
            String idToken = signedIdToken("sherlock", List.of("ROLE_ADMIN"));
            assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(idToken));
            assertUnauthorized(client, HttpRequest.GET("/username").cookie(Cookie.of("JWT", idToken)));
            assertUnauthorized(client, HttpRequest.GET("/admin").bearerAuth(idToken));
            assertUnauthorized(client, HttpRequest.GET("/admin").cookie(Cookie.of("JWT", idToken)));
        }
    }

    @Test
    void disabledClientRegistersNeitherProviderMetadataNorJwks() {
        try (EmbeddedServer server = startRelyingParty(false)) {
            assertTrue(server.getApplicationContext().getBeansOfType(DefaultOpenIdProviderMetadata.class).isEmpty());
            assertTrue(server.getApplicationContext().getBeansOfType(JwksSignatureConfiguration.class).isEmpty());
        }
        try (EmbeddedServer server = startRelyingParty(true)) {
            assertFalse(server.getApplicationContext().getBeansOfType(DefaultOpenIdProviderMetadata.class).isEmpty());
            assertFalse(server.getApplicationContext().getBeansOfType(JwksSignatureConfiguration.class).isEmpty());
        }
    }

    @Test
    void unsignedTokensAreRejectedWhetherClientIsEnabledOrDisabled() {
        for (boolean clientEnabled : new boolean[] {true, false}) {
            for (boolean claimsValidatorEnabled : new boolean[] {true, false}) {
                Map<String, Object> extra = claimsValidatorEnabled
                    ? Map.of()
                    : Map.of("micronaut.security.token.jwt.claims-validators.openid-idtoken", false);
                try (EmbeddedServer server = startRelyingParty(clientEnabled, extra);
                     HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    BlockingHttpClient client = httpClient.toBlocking();
                    String unsigned = unsignedIdToken("attacker", List.of("ROLE_ADMIN"));
                    String scenario = "client enabled=" + clientEnabled + ", claims validator enabled=" + claimsValidatorEnabled;
                    assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(unsigned), scenario);
                    assertUnauthorized(client, HttpRequest.GET("/username").cookie(Cookie.of("JWT", unsigned)), scenario);
                    assertUnauthorized(client, HttpRequest.GET("/admin").bearerAuth(unsigned), scenario);
                    assertUnauthorized(client, HttpRequest.GET("/admin").cookie(Cookie.of("JWT", unsigned)), scenario);
                }
            }
        }
    }

    @Test
    void unsignedTokensAreRejectedWhenNoClientIsConfigured() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.authentication", "idtoken");
        configuration.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertTrue(server.getApplicationContext().getBeansOfType(JwksSignatureConfiguration.class).isEmpty());
            String unsigned = unsignedIdToken("attacker", List.of("ROLE_ADMIN"));
            assertUnauthorized(httpClient.toBlocking(), HttpRequest.GET("/admin").bearerAuth(unsigned), "no OAuth 2.0 client configured");
        }
    }

    @Test
    void idTokensIssuedToDisabledClientAreRejectedEvenWithoutClaimsValidator() {
        try (EmbeddedServer server = startRelyingParty(false, Map.of("micronaut.security.token.jwt.claims-validators.openid-idtoken", false));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(signedIdToken("sherlock", List.of("ROLE_ADMIN"))));
        }
    }

    @Test
    void providerResolverAndWellKnownProxyIgnoreDisabledClients() throws MalformedURLException {
        OauthClientConfiguration enabled = clientConfiguration("enabled-client", true);
        OauthClientConfiguration disabled = clientConfiguration("disabled-client", false);
        io.micronaut.security.oauth2.DefaultProviderResolver resolver = new io.micronaut.security.oauth2.DefaultProviderResolver(
            List.of(disabled.getOpenid().get()), List.of(disabled));
        assertTrue(resolver.resolveProvider(io.micronaut.security.authentication.Authentication.build("sherlock", Map.of("iss", "https://issuer.example.com"))).isEmpty());
        resolver = new io.micronaut.security.oauth2.DefaultProviderResolver(
            List.of(enabled.getOpenid().get()), List.of(enabled));
        assertEquals(Optional.of("enabled-client"), resolver.resolveProvider(io.micronaut.security.authentication.Authentication.build("sherlock", Map.of("iss", "https://issuer.example.com"))));
    }

    @Test
    void enabledSiblingOfDisabledClientIsInitializedAtStartupAndIsolated() {
        AtomicInteger discoveries = fakeProvider().discoveries;
        Map<String, Object> sibling = new HashMap<>();
        sibling.put("micronaut.security.oauth2.clients.active.client-id", SIBLING_CLIENT_ID);
        sibling.put("micronaut.security.oauth2.clients.active.client-secret", "test-fixture-not-a-secret");
        sibling.put("micronaut.security.oauth2.clients.active.openid.issuer", issuer());
        int before = discoveries.get();
        try (EmbeddedServer server = startRelyingParty(false, sibling);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertEquals(1, server.getApplicationContext().getBeanDefinitions(DefaultOpenIdProviderMetadata.class).size(),
                "a disabled client must not be a bean definition candidate: a candidate that throws during eager initialization stops its siblings from being initialized");
            assertEquals(before + 1, discoveries.get(),
                "the enabled client must fetch its provider metadata at startup although a disabled sibling precedes it");
            assertEquals(List.of("active"),
                server.getApplicationContext().getBeansOfType(DefaultOpenIdProviderMetadata.class).stream().map(DefaultOpenIdProviderMetadata::getName).toList());

            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/admin").accept(MediaType.TEXT_PLAIN)
                .bearerAuth(signedIdToken("sherlock", List.of("ROLE_ADMIN"), SIBLING_CLIENT_ID))));
            assertUnauthorized(client, HttpRequest.GET("/admin").bearerAuth(signedIdToken("sherlock", List.of("ROLE_ADMIN"), CLIENT_ID)),
                "token issued to the disabled client, signed with the keys the enabled sibling trusts");
            assertUnauthorized(client, HttpRequest.GET("/username").cookie(Cookie.of("JWT", signedIdToken("sherlock", List.of("ROLE_ADMIN"), CLIENT_ID))),
                "token issued to the disabled client, signed with the keys the enabled sibling trusts");
        }
    }

    @Test
    void idTokensIssuedToEnabledClientAreAccepted() {
        try (EmbeddedServer server = startRelyingParty(true);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertTrue(server.getApplicationContext().containsBean(OpenIdClient.class));
            BlockingHttpClient client = httpClient.toBlocking();
            String idToken = signedIdToken("sherlock", List.of("ROLE_ADMIN"));
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/username").accept(MediaType.TEXT_PLAIN).bearerAuth(idToken)));
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/admin").accept(MediaType.TEXT_PLAIN).cookie(Cookie.of("JWT", idToken))));

            String idTokenWithoutAdminRole = signedIdToken("watson", List.of("ROLE_USER"));
            assertEquals("watson", client.retrieve(HttpRequest.GET("/username").accept(MediaType.TEXT_PLAIN).bearerAuth(idTokenWithoutAdminRole)));
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(HttpRequest.GET("/admin").accept(MediaType.TEXT_PLAIN).bearerAuth(idTokenWithoutAdminRole)));
            assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
        }
    }

    @Test
    void validatorIgnoresDisabledClientConfigurations() throws MalformedURLException {
        OauthClientConfiguration enabled = clientConfiguration("enabled-client", true);
        OauthClientConfiguration disabled = clientConfiguration("disabled-client", false);
        MapClaims claims = new MapClaims(Map.of(
            "iss", "https://issuer.example.com",
            "aud", CLIENT_ID,
            "sub", "sherlock"));

        assertTrue(new IdTokenClaimsValidator<>(List.of(enabled)).validate(claims, null));
        assertFalse(new IdTokenClaimsValidator<>(List.of(disabled)).validate(claims, null));
        assertTrue(new IdTokenClaimsValidator<>(List.of(disabled, enabled)).validate(claims, null),
            "an enabled client matching the token must still accept it");
    }

    private static OauthClientConfiguration clientConfiguration(String name, boolean enabled) throws MalformedURLException {
        OpenIdClientConfiguration openid = mock(OpenIdClientConfiguration.class);
        when(openid.getName()).thenReturn(name);
        when(openid.getIssuer()).thenReturn(Optional.of(new URL("https://issuer.example.com")));
        when(openid.getIssuerIdentifier()).thenReturn(Optional.of("https://issuer.example.com"));
        return OauthClientConfiguration.builder()
            .name(name)
            .clientId(CLIENT_ID)
            .clientSecret("test-fixture-not-a-secret")
            .enabled(enabled)
            .openid(openid)
            .build();
    }

    private static EmbeddedServer startRelyingParty(boolean clientEnabled) {
        return startRelyingParty(clientEnabled, Map.of());
    }

    private static EmbeddedServer startRelyingParty(boolean clientEnabled, Map<String, Object> extra) {
        Map<String, Object> configuration = new HashMap<>(extra);
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.authentication", "idtoken");
        configuration.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        configuration.put("micronaut.security.oauth2.clients.auth.enabled", clientEnabled);
        configuration.put("micronaut.security.oauth2.clients.auth.client-id", CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.auth.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.auth.openid.issuer", issuer());
        return ApplicationContext.run(EmbeddedServer.class, configuration);
    }

    private static ProviderController fakeProvider() {
        return provider.getApplicationContext().getBean(ProviderController.class);
    }

    private static String issuer() {
        return provider.getURL() + ISSUER_PATH;
    }

    /**
     * An unsigned ({@code alg: none}) token anyone can forge without a signing key.
     */
    private static String unsignedIdToken(String subject, List<String> roles) {
        return new PlainJWT(claims(subject, roles, CLIENT_ID)).serialize();
    }

    private static JWTClaimsSet claims(String subject, List<String> roles, String audience) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
            .issuer(issuer())
            .subject(subject)
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)))
            .claim("roles", roles)
            .build();
    }

    private static String signedIdToken(String subject, List<String> roles) {
        return signedIdToken(subject, roles, CLIENT_ID);
    }

    private static String signedIdToken(String subject, List<String> roles, String audience) {
        JWTClaimsSet claims = claims(subject, roles, audience);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(PROVIDER_KEY.getKeyID()).build(), claims);
        try {
            jwt.sign(new RSASSASigner(PROVIDER_KEY));
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

    private static void assertUnauthorized(BlockingHttpClient client, MutableHttpRequest<?> request) {
        assertUnauthorized(client, request, "");
    }

    private static void assertUnauthorized(BlockingHttpClient client, MutableHttpRequest<?> request, String scenario) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> "GET " + request.getUri() + " should have been rejected. " + scenario);
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus(), () -> "GET " + request.getUri() + ". " + scenario);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    @Produces(MediaType.TEXT_PLAIN)
    static class EchoController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/username")
        String username(Principal principal) {
            return principal.getName();
        }

        @Secured("ROLE_ADMIN")
        @Get("/admin")
        String admin(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;
        final AtomicInteger discoveries = new AtomicInteger();

        ProviderController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            discoveries.incrementAndGet();
            String issuer = httpHostResolver.resolve(request) + ISSUER_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/v1/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/v1/token\","
                + "\"userinfo_endpoint\":\"" + issuer + "/v1/userinfo\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"response_types_supported\":[\"code\",\"id_token\",\"code id_token\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"scopes_supported\":[\"openid\",\"profile\",\"email\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        String keys() {
            return new JWKSet(PROVIDER_KEY.toPublicJWK()).toString();
        }
    }
}
