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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.NonUniqueBeanException;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The authorization code flow of an OpenID client must map the ID token with a provider-specific
 * {@link OpenIdAuthenticationMapper} when one is registered for the client, otherwise with the application's
 * global mapper: the one without a qualifier. A mapper registered for another client must never decide who is
 * authenticated through a client without a mapper of its own.
 */
class OpenIdAuthorizationCodeGlobalMapperTest {
    private static final String AUTH_SERVER = "OpenIdAuthorizationCodeGlobalMapperTestAuthServer";
    private static final String APP = "OpenIdAuthorizationCodeGlobalMapperTestApp";
    private static final String GLOBAL_MAPPER_PROPERTY = "global-mapper";
    private static final String CLIENT_ID = "myclient";
    private static final String CLIENT_NAME = "authserver";
    private static final String CLIENT_SECRET = "test-fixture-not-a-secret";
    private static final String ADMITTED_USER = "alice";
    private static final String REJECTED_USER = "mallory";
    private static final String JWT_COOKIE = "JWT";

    @ParameterizedTest
    @ValueSource(strings = {"primary", "replaces", "replaces-and-named-other"})
    void userRefusedByGlobalMapperCannotLogIn(String globalMapper) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertTrue(authenticate(client, REJECTED_USER).isEmpty(), "the refused user must not receive a JWT cookie");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"primary", "replaces", "replaces-and-named-other"})
    void userAdmittedByGlobalMapperGetsTheNameAndRolesItAssigns(String globalMapper) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("alice@example.com ROLE_ADMIN", whoAmI(client, ADMITTED_USER));
        }
    }

    @Test
    void providerSpecificMapperTakesPrecedenceOverGlobalMapper() {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, "replaces-and-named");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("named:mallory ROLE_USER", whoAmI(client, REJECTED_USER));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "named-other"})
    void defaultMapperIsUsedWhenNoGlobalMapperIsRegistered(String globalMapper) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("alice", whoAmI(client, ADMITTED_USER));
        }
    }

    /**
     * A mapper registered for another client is never the global mapper, even when it is the only mapper left
     * because it replaces the default one. The client without a mapper is then not created: nobody can log in
     * through it, instead of the other client's mapper deciding who is admitted.
     */
    @ParameterizedTest
    @ValueSource(strings = {"other-client-replaces-default", "named-other-and-another"})
    void mappersOfOtherClientsOnlyDisableTheClient(String globalMapper) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertTrue(app.getApplicationContext().getBeansOfType(OpenIdClient.class).isEmpty(),
                "no OpenID client must be created without a global mapper");
            BlockingHttpClient client = httpClient.toBlocking();
            assertTrue(authenticate(client, ADMITTED_USER).isEmpty(), "nobody must receive a JWT cookie");
            assertTrue(authenticate(client, REJECTED_USER).isEmpty(), "nobody must receive a JWT cookie");
        }
    }

    /**
     * A custom {@link OpenIdAuthorizationResponseHandler} may authenticate without a mapper, so the client is still
     * created for it when the only mapper belongs to another client. The mapper requirement only applies to
     * {@link DefaultOpenIdAuthorizationResponseHandler} itself: a subclass which overrides
     * {@link DefaultOpenIdAuthorizationResponseHandler#handle} is a custom handler too.
     */
    @ParameterizedTest
    @ValueSource(strings = {"other-client-replaces-default-custom-handler", "other-client-replaces-default-custom-handler-subclass"})
    void customAuthorizationResponseHandlerDoesNotRequireAMapper(String globalMapper) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(authServer, globalMapper);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertEquals(1, app.getApplicationContext().getBeansOfType(OpenIdClient.class).size(),
                "the OpenID client must be created for a custom authorization response handler");
            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("custom-handler ROLE_CUSTOM", whoAmI(client, ADMITTED_USER));
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
        return ApplicationContext.run(EmbeddedServer.class, CollectionUtils.mapOf(
            "spec.name", APP,
            GLOBAL_MAPPER_PROPERTY, globalMapper,
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false,
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-secret", CLIENT_SECRET,
            "micronaut.security.oauth2.clients." + CLIENT_NAME + ".openid.issuer", issuer(authServer)));
    }

    private static String issuer(EmbeddedServer authServer) {
        return "http://localhost:" + authServer.getPort() + "/oauth2/default";
    }

    /**
     * Runs the authorization code flow for the given user: starts the login to obtain the state and nonce, then
     * delivers the authorization response to the callback. The mock provider issues an ID token for the user named
     * in the code, carrying the nonce the application sent.
     *
     * @return The JWT cookie issued by the application, or empty when the user was not logged in
     */
    private static Optional<String> authenticate(BlockingHttpClient client, String username) {
        HttpResponse<?> redirect = exchange(client, HttpRequest.GET("/oauth/login/" + CLIENT_NAME));
        if (redirect.status() != HttpStatus.FOUND) {
            return Optional.empty();
        }
        String location = redirect.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        Map<String, String> parameters = queryParameters(URI.create(location));
        String state = parameters.get("state");
        String nonce = parameters.get("nonce");
        assertNotNull(state, "the authorization request must carry a state");
        assertNotNull(nonce, "the authorization request must carry a nonce");
        MutableHttpRequest<?> callback = HttpRequest.POST("/oauth/callback/" + CLIENT_NAME,
                CollectionUtils.mapOf("code", username + ":" + nonce, "state", state))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED);
        for (Cookie cookie : redirect.getCookies().getAll()) {
            callback.cookie(cookie);
        }
        HttpResponse<?> response = exchange(client, callback);
        return Optional.ofNullable(response.getCookies().get(JWT_COOKIE)).map(Cookie::getValue);
    }

    private static String whoAmI(BlockingHttpClient client, String username) {
        String jwt = authenticate(client, username).orElseThrow(() -> new AssertionError("user " + username + " was not logged in"));
        return client.retrieve(HttpRequest.GET("/").cookie(Cookie.of(JWT_COOKIE, jwt)));
    }

    private static HttpResponse<?> exchange(BlockingHttpClient client, HttpRequest<?> request) {
        try {
            return client.exchange(request);
        } catch (HttpClientResponseException e) {
            return e.getResponse();
        }
    }

    private static Map<String, String> queryParameters(URI uri) {
        Map<String, String> parameters = new HashMap<>();
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                int i = pair.indexOf('=');
                String name = URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), StandardCharsets.UTF_8);
                String value = i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
                parameters.put(name, value);
            }
        }
        return parameters;
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
     * Mapper registered for another OpenID client. It admits everybody, so that a login succeeding would prove it
     * was used for {@value #CLIENT_NAME}.
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
            return Mono.just(AuthenticationResponse.success("other:" + openIdClaims.getSubject(), List.of("ROLE_ADMIN")));
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
     * The only mapper of the application, registered for another client and replacing the default one.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, pattern = "other-client-replaces-default.*")
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
     * Authorization response handler which authenticates without any {@link OpenIdAuthenticationMapper}.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "other-client-replaces-default-custom-handler")
    @Replaces(DefaultOpenIdAuthorizationResponseHandler.class)
    @Singleton
    static class CustomAuthorizationResponseHandler implements OpenIdAuthorizationResponseHandler {
        @Override
        public Publisher<AuthenticationResponse> handle(OpenIdAuthorizationResponse authorizationResponse,
                                                        OauthClientConfiguration clientConfiguration,
                                                        OpenIdProviderMetadata openIdProviderMetadata,
                                                        @Nullable OpenIdAuthenticationMapper authenticationMapper,
                                                        SecureEndpoint tokenEndpoint) {
            return Mono.just(AuthenticationResponse.success("custom-handler", List.of("ROLE_CUSTOM")));
        }
    }

    /**
     * Subclass of {@link DefaultOpenIdAuthorizationResponseHandler} which overrides {@code handle} to authenticate
     * without any {@link OpenIdAuthenticationMapper}. Inheriting from the default handler does not mean it needs a mapper.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = GLOBAL_MAPPER_PROPERTY, value = "other-client-replaces-default-custom-handler-subclass")
    @Replaces(DefaultOpenIdAuthorizationResponseHandler.class)
    @Singleton
    static class SubclassAuthorizationResponseHandler<T> extends DefaultOpenIdAuthorizationResponseHandler<T> {
        SubclassAuthorizationResponseHandler(ReactiveOpenIdTokenResponseValidator<JWT> tokenResponseValidator,
                                             BeanContext beanContext,
                                             TokenEndpointClient tokenEndpointClient,
                                             OauthRouteUrlBuilder<T> oauthRouteUrlBuilder,
                                             @Nullable StateValidator stateValidator,
                                             @Nullable PkcePersistence pkcePersistence) {
            super(tokenResponseValidator, beanContext, tokenEndpointClient, oauthRouteUrlBuilder, stateValidator, pkcePersistence);
        }

        @Override
        public Publisher<AuthenticationResponse> handle(OpenIdAuthorizationResponse authorizationResponse,
                                                        OauthClientConfiguration clientConfiguration,
                                                        OpenIdProviderMetadata openIdProviderMetadata,
                                                        @Nullable OpenIdAuthenticationMapper authenticationMapper,
                                                        SecureEndpoint tokenEndpoint) {
            return Mono.just(AuthenticationResponse.success("custom-handler", List.of("ROLE_CUSTOM")));
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

        /**
         * Redeems a code of the form {@code <subject>:<nonce>} for an ID token of that subject carrying that nonce.
         */
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/token")
        HttpResponse<String> token(@Body("grant_type") String grantType,
                                   @Body("code") String code) throws JOSEException {
            int separator = code.indexOf(':');
            if (!"authorization_code".equals(grantType) || separator < 0) {
                return HttpResponse.badRequest("{\"error\":\"invalid_grant\"}").contentType(MediaType.APPLICATION_JSON_TYPE);
            }
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer(embeddedServer))
                .subject(code.substring(0, separator))
                .audience(CLIENT_ID)
                .claim("nonce", code.substring(separator + 1))
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
