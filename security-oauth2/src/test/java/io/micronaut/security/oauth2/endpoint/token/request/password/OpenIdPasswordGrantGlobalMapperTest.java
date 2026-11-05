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
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.NonUniqueBeanException;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The password grant flow of an OpenID client must map the ID token with the same
 * {@link OpenIdAuthenticationMapper} the authorization code flow uses: a provider-specific
 * mapper when one is registered for the client, otherwise the application's global mapper.
 * A user the global mapper refuses must not be able to log in through the password grant.
 */
class OpenIdPasswordGrantGlobalMapperTest {
    private static final String AUTH_SERVER = "OpenIdPasswordGrantGlobalMapperTestAuthServer";
    private static final String APP = "OpenIdPasswordGrantGlobalMapperTestApp";
    private static final String GLOBAL_MAPPER_PROPERTY = "global-mapper";
    private static final String CLIENT_ID = "myclient";
    private static final String CLIENT_NAME = "authserver";
    private static final String PASSWORD = "test-fixture-not-a-secret";
    private static final String ADMITTED_USER = "alice";
    private static final String REJECTED_USER = "mallory";

    @ParameterizedTest
    @ValueSource(strings = {"primary", "replaces"})
    void userRefusedByGlobalMapperCannotLogInWithPasswordGrant(String globalMapper) throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertLoginUnauthorized(client, REJECTED_USER, PASSWORD);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"primary", "replaces"})
    void userAdmittedByGlobalMapperGetsTheNameAndRolesItAssigns(String globalMapper) throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            String accessToken = login(client, ADMITTED_USER, PASSWORD);
            assertEquals("alice@example.com ROLE_ADMIN", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
            assertEquals("admin", client.retrieve(HttpRequest.GET("/admin").bearerAuth(accessToken)));
        }
    }

    @Test
    void providerSpecificMapperTakesPrecedenceOverGlobalMapper() throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, "replaces-and-named");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            String accessToken = login(client, REJECTED_USER, PASSWORD);
            assertEquals("named:mallory ROLE_USER", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
        }
    }

    @Test
    void primaryGlobalMapperAppliesToClientsWithoutAProviderSpecificMapper() throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, "primary-and-named-other");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertLoginUnauthorized(client, REJECTED_USER, PASSWORD);
            String accessToken = login(client, ADMITTED_USER, PASSWORD);
            assertEquals("alice@example.com ROLE_ADMIN", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
        }
    }

    /**
     * When the default mapper is replaced and a mapper is registered for another client only, the bean without a
     * qualifier is the global mapper. The mapper of the other client must not be used.
     */
    @Test
    void unqualifiedGlobalMapperIsPreferredOverMappersOfOtherClients() throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, "replaces-and-named-other");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertLoginUnauthorized(client, REJECTED_USER, PASSWORD);
            String accessToken = login(client, ADMITTED_USER, PASSWORD);
            assertEquals("alice@example.com ROLE_ADMIN", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
        }
    }

    /**
     * A mapper registered for another client is never the global mapper, even when it is the only mapper left
     * because it replaces the default one. The password grant of a client without a mapper is then disabled:
     * nobody can log in through it, instead of the other client's mapper deciding who is admitted.
     */
    @ParameterizedTest
    @ValueSource(strings = {"other-client-replaces-default", "named-other-and-another"})
    void mappersOfOtherClientsOnlyDisableThePasswordGrant(String globalMapper) throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertTrue(app.getApplicationContext().getBeansOfType(ReactiveAuthenticationProvider.class).isEmpty(),
                "no password grant authentication provider must be created without a global mapper");
            BlockingHttpClient client = httpClient.toBlocking();
            assertLoginUnauthorized(client, ADMITTED_USER, PASSWORD);
            assertLoginUnauthorized(client, REJECTED_USER, PASSWORD);
        }
    }

    /**
     * With several unqualified candidates and no primary one, the global mapper is ambiguous: the application must
     * fail to start instead of picking one of them.
     */
    @Test
    void ambiguousUnqualifiedGlobalMapperFailsAtStartup() {
        try (EmbeddedServer authServer = startAuthServer()) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class, () -> {
                try (EmbeddedServer app = startApp(authServer, "replaces-twice")) {
                    fail("application started with an ambiguous global OpenIdAuthenticationMapper: " + app.getURL());
                }
            });
            assertInstanceOf(NonUniqueBeanException.class, rootCause(e));
        }
    }

    @Test
    void defaultMapperIsUsedWhenNoGlobalMapperIsRegistered() throws Exception {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, "none");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            String accessToken = login(client, ADMITTED_USER, PASSWORD);
            assertEquals("alice", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
            // A wrong password must never log the user in. The provider's invalid_grant currently surfaces as a
            // 500 rather than a 401, which is pre-existing behaviour of the password grant provider.
            HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(loginRequest(ADMITTED_USER, "wrong-password-fixture")));
            assertNotEquals(HttpStatus.OK, e.getStatus());
        }
    }

    private static Throwable rootCause(Throwable t) {
        while (t.getCause() != null && t.getCause() != t) {
            t = t.getCause();
        }
        return t;
    }

    private static EmbeddedServer startAuthServer() {
        return ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER));
    }

    private static EmbeddedServer startApp(EmbeddedServer authServer, String globalMapper) {
        return ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", APP,
            GLOBAL_MAPPER_PROPERTY, globalMapper,
            "micronaut.security.authentication", "bearer",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".grant-type", "password",
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-secret", PASSWORD,
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".openid.issuer", issuer(authServer)));
    }

    private static String issuer(EmbeddedServer authServer) {
        return "http://localhost:" + authServer.getPort() + "/oauth2/default";
    }

    private static String login(BlockingHttpClient client, String username, String password) {
        Map<String, Object> body = client.retrieve(loginRequest(username, password), Argument.mapOf(String.class, Object.class));
        Object accessToken = body.get("access_token");
        assertNotNull(accessToken, "login response must contain an access token");
        return accessToken.toString();
    }

    private static void assertLoginUnauthorized(BlockingHttpClient client, String username, String password) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(loginRequest(username, password)));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    private static HttpRequest<?> loginRequest(String username, String password) {
        return HttpRequest.POST("/login", new UsernamePasswordCredentials(username, password));
    }

    /**
     * Global mapper that only admits {@value #ADMITTED_USER}, giving them a different name and the admin role.
     */
    abstract static class AllowlistMapper implements OpenIdAuthenticationMapper {
        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                              OpenIdTokenResponse tokenResponse,
                                                                              OpenIdClaims openIdClaims,
                                                                              @Nullable State state) {
            if (ADMITTED_USER.equals(openIdClaims.getSubject())) {
                return Mono.just(AuthenticationResponse.success("alice@example.com", List.of("ROLE_ADMIN")));
            }
            return Mono.just(AuthenticationResponse.failure("user is not allowed"));
        }
    }

    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, pattern = "primary.*")
    @Primary
    @Singleton
    static class PrimaryGlobalMapper extends AllowlistMapper {
    }

    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, pattern = "replaces.*")
    @Replaces(DefaultOpenIdAuthenticationMapper.class)
    @Singleton
    static class ReplacingGlobalMapper extends AllowlistMapper {
    }

    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "replaces-and-named")
    @Named(CLIENT_NAME)
    @Singleton
    static class ProviderSpecificMapper implements OpenIdAuthenticationMapper {
        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                              OpenIdTokenResponse tokenResponse,
                                                                              OpenIdClaims openIdClaims,
                                                                              @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("named:" + openIdClaims.getSubject(), List.of("ROLE_USER")));
        }
    }

    /**
     * Mapper registered for another OpenID client. It must not be used for {@value #CLIENT_NAME}.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, pattern = ".*named-other.*")
    @Named("other")
    @Singleton
    static class OtherProviderMapper implements OpenIdAuthenticationMapper {
        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                              OpenIdTokenResponse tokenResponse,
                                                                              OpenIdClaims openIdClaims,
                                                                              @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("other:" + openIdClaims.getSubject()));
        }
    }

    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "named-other-and-another")
    @Named("another")
    @Replaces(DefaultOpenIdAuthenticationMapper.class)
    @Singleton
    static class AnotherProviderMapper extends AllowlistMapper {
    }

    /**
     * The only mapper of the application, registered for another client. It admits everybody, so that a login
     * succeeding would prove it was used for {@value #CLIENT_NAME}.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "other-client-replaces-default")
    @Named("other")
    @Replaces(DefaultOpenIdAuthenticationMapper.class)
    @Singleton
    static class SoleOtherProviderMapper implements OpenIdAuthenticationMapper {
        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                              OpenIdTokenResponse tokenResponse,
                                                                              OpenIdClaims openIdClaims,
                                                                              @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("other:" + openIdClaims.getSubject(), List.of("ROLE_ADMIN")));
        }
    }

    /**
     * A second unqualified global mapper, making the global mapper ambiguous together with {@link ReplacingGlobalMapper}.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "replaces-twice")
    @Replaces(DefaultOpenIdAuthenticationMapper.class)
    @Singleton
    static class SecondReplacingGlobalMapper extends AllowlistMapper {
    }

    @Requires(property = "spec.name", value = APP)
    @Controller("/")
    static class HomeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Authentication authentication) {
            StringBuilder sb = new StringBuilder(authentication.getName());
            for (String role : authentication.getRoles()) {
                sb.append(' ').append(role);
            }
            return sb.toString();
        }

        @Secured("ROLE_ADMIN")
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/admin")
        String admin() {
            return "admin";
        }
    }

    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Singleton
    static class ProviderKey {
        final RSAKey key;

        ProviderKey() throws JOSEException {
            this.key = new RSAKeyGenerator(2048).keyID("test-key").generate();
        }
    }

    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Controller("/oauth2/default")
    static class MockOpenIdProviderController {
        private final ProviderKey providerKey;
        private final EmbeddedServer embeddedServer;

        MockOpenIdProviderController(ProviderKey providerKey, EmbeddedServer embeddedServer) {
            this.providerKey = providerKey;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        HttpResponse<String> configuration() {
            String issuer = issuer(embeddedServer);
            return HttpResponse.ok("""
                {
                  "issuer": "%s",
                  "authorization_endpoint": "%s/authorize",
                  "token_endpoint": "%s/token",
                  "jwks_uri": "%s/keys",
                  "response_types_supported": ["code"],
                  "subject_types_supported": ["public"],
                  "id_token_signing_alg_values_supported": ["RS256"],
                  "token_endpoint_auth_methods_supported": ["client_secret_basic"]
                }
                """.formatted(issuer, issuer, issuer, issuer)).contentType(MediaType.APPLICATION_JSON_TYPE);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/keys")
        HttpResponse<String> keys() {
            return HttpResponse.ok(new JWKSet(providerKey.key.toPublicJWK()).toString()).contentType(MediaType.APPLICATION_JSON_TYPE);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/token")
        HttpResponse<String> token(@Body("grant_type") String grantType,
                                   @Body("username") String username,
                                   @Body("password") String password) throws JOSEException {
            if (!"password".equals(grantType) || !PASSWORD.equals(password)) {
                return HttpResponse.badRequest("{\"error\":\"invalid_grant\"}").contentType(MediaType.APPLICATION_JSON_TYPE);
            }
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer(embeddedServer))
                .subject(username)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofHours(1))))
                .build();
            SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(providerKey.key.getKeyID()).build(), claims);
            idToken.sign(new RSASSASigner(providerKey.key));
            return HttpResponse.ok("""
                {
                  "access_token": "opaque-access-token-fixture",
                  "id_token": "%s",
                  "token_type": "Bearer",
                  "expires_in": 3600
                }
                """.formatted(idToken.serialize())).contentType(MediaType.APPLICATION_JSON_TYPE);
        }
    }
}
