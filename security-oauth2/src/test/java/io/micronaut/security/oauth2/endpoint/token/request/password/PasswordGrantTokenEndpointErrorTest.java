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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
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
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.ThrowableAuthenticationResponseAdapter;
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A password grant the token endpoint of the OAuth 2.0 or OpenID provider rejects with a 4xx response
 * (RFC 6749 section 5.2, for example {@code invalid_grant} for a wrong password) is an authentication failure:
 * {@code POST /login} must answer 401, not 500. A provider outage (a 5xx response or a connection failure) is not
 * an authentication failure and keeps surfacing as a server error, and neither is a transient 4xx response such as
 * {@code 429 Too Many Requests} or {@code 400 temporarily_unavailable}, a rejection of the client such as
 * {@code 401 invalid_client} or a {@code 404} of a wrong token URL (both logged at WARN), or an error of the
 * authentication mapper.
 */
class PasswordGrantTokenEndpointErrorTest {
    private static final String AUTH_SERVER = "PasswordGrantTokenEndpointErrorTestAuthServer";
    private static final String APP = "PasswordGrantTokenEndpointErrorTestApp";
    private static final String CLIENT_TYPE_PROPERTY = "client-type";
    private static final String OPENID = "openid";
    private static final String OAUTH = "oauth";
    private static final String CLIENT_ID = "myclient";
    private static final String CLIENT_NAME = "authserver";
    private static final String CLIENT_SECRET = "client-secret-fixture-not-a-secret";
    private static final String PASSWORD = "password-fixture-not-a-secret";
    private static final String WRONG_PASSWORD = "wrong-password-fixture";
    private static final String ERROR_DESCRIPTION = "the provider's description of the rejection";
    private static final String USER = "alice";
    private static final String USER_INVALID_CLIENT = "invalid-client";
    private static final String USER_UNKNOWN_ERROR_CODE = "unknown-error-code";
    private static final String USER_FORBIDDEN = "forbidden";
    private static final String USER_OUTAGE = "outage";
    private static final String USER_THROTTLED = "throttled";
    private static final String USER_TEMPORARILY_UNAVAILABLE = "temporarily-unavailable";
    private static final String USER_SERVER_ERROR_CODE = "server-error-code";
    private static final String USER_NOT_FOUND = "not-found";
    private static final String USER_MALFORMED_BODY = "malformed-body";
    private static final String USER_EMPTY_BODY = "empty-body";
    private static final String USER_NON_STRING_ERROR = "non-string-error";
    private static final String USER_UNKNOWN_STATUS = "unknown-status";
    private static final String LOCAL_USER = "local-user";
    private static final String LOCAL_PASSWORD = "local-password-fixture-not-a-secret";
    private static final String LOCAL_PROVIDER_PROPERTY = "local-provider";
    private static final String MAPPER_ERROR_PROPERTY = "mapper-error";
    private static final String MAPPER_SUCCEEDS = "none";
    private static final String MAPPER_EMITS = "emits";
    private static final String MAPPER_THROWS = "throws";
    private static final String VALIDATOR_THROWS = "validator-throws";

    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void wrongPasswordIsUnauthorizedAndCorrectPasswordLogsIn(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            LoginFailedEvents events = app.getApplicationContext().getBean(LoginFailedEvents.class);

            assertLoginUnauthorized(client, USER, WRONG_PASSWORD);
            assertEquals(1, events.responses.size());
            AuthenticationFailed failure = assertInstanceOf(AuthenticationFailed.class, events.responses.get(0));
            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, failure.getReason());

            String accessToken = login(client, USER, PASSWORD);
            assertEquals(OPENID.equals(clientType) ? USER : "oauth-user", client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
            assertEquals(1, events.responses.size());
        }
    }

    /**
     * RFC 6749 section 5.2: {@code invalid_client} rejects the client, not the user's password. Answered as a failed
     * login, a rotated client secret would surface as a 401 for every user and feed each user's lockout counter, so
     * it is propagated as before and, since it is never user-caused, logged at WARN.
     */
    @ParameterizedTest
    @CsvSource({
        OPENID + "," + USER_INVALID_CLIENT + ",401,invalid_client",
        OAUTH + "," + USER_INVALID_CLIENT + ",401,invalid_client",
        OPENID + "," + USER_NOT_FOUND + ",404,unknown",
        OAUTH + "," + USER_NOT_FOUND + ",404,unknown"})
    void rejectionOfTheClientIsAServerErrorLoggedAtWarn(String clientType, String username, int status, String errorCode) {
        ListAppender<ILoggingEvent> appender = adapterLog(Level.WARN);
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), username, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "a rejection of the client must not be published as a failed login");
        } finally {
            detach(appender);
        }
        List<ILoggingEvent> warnings = appender.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).toList();
        assertEquals(1, warnings.size(), () -> "one WARN message expected, got " + warnings);
        String message = warnings.get(0).getFormattedMessage();
        assertTrue(message.contains("[" + CLIENT_NAME + "]"), message);
        assertTrue(message.contains("HTTP status " + status + " and error code [" + errorCode + "]"), message);
        assertFalse(message.contains(ERROR_DESCRIPTION), "the log must not relay the provider's error description");
        assertFalse(message.contains(PASSWORD), "the log must not contain the password");
        assertFalse(message.contains(CLIENT_SECRET), "the log must not contain the client secret");
    }

    /**
     * Providers extend the error codes of RFC 6749. A body whose error code is not a {@code TokenError} is still a
     * rejection, and its error code is still logged at {@code DEBUG}, without the error description.
     */
    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void unknownErrorCodeIsUnauthorizedAndLogged(String clientType) {
        ListAppender<ILoggingEvent> appender = adapterLog(Level.DEBUG);
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginUnauthorized(httpClient.toBlocking(), USER_UNKNOWN_ERROR_CODE, PASSWORD);
            assertSingleFailure(app, AuthenticationFailureReason.UNKNOWN);
        } finally {
            detach(appender);
        }
        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertEquals(1, messages.size(), () -> "one DEBUG message expected, got " + messages);
        assertTrue(messages.get(0).contains("HTTP status 400 and error code [account_locked]"), messages.get(0));
        assertFalse(messages.get(0).contains(ERROR_DESCRIPTION), "the log must not relay the provider's error description");
        assertFalse(messages.get(0).contains(PASSWORD), "the log must not contain the password");
        assertFalse(messages.get(0).contains(CLIENT_SECRET), "the log must not contain the client secret");
    }

    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void forbiddenWithoutJsonBodyIsUnauthorized(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginUnauthorized(httpClient.toBlocking(), USER_FORBIDDEN, PASSWORD);
            assertSingleFailure(app, AuthenticationFailureReason.UNKNOWN);
        }
    }

    /**
     * A 4xx response declared as JSON whose body is not a token error response (malformed, empty, or with an
     * {@code error} member which is not a string) is still a rejection, with an unknown reason.
     */
    @ParameterizedTest
    @CsvSource({
        OPENID + "," + USER_MALFORMED_BODY,
        OAUTH + "," + USER_MALFORMED_BODY,
        OPENID + "," + USER_EMPTY_BODY,
        OAUTH + "," + USER_EMPTY_BODY,
        OPENID + "," + USER_NON_STRING_ERROR,
        OAUTH + "," + USER_NON_STRING_ERROR})
    void aJsonBodyWhichIsNotATokenErrorResponseIsUnauthorized(String clientType, String username) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginUnauthorized(httpClient.toBlocking(), username, PASSWORD);
            assertSingleFailure(app, AuthenticationFailureReason.UNKNOWN);
        }
    }

    /**
     * {@code HttpClientResponseException#getStatus()} throws for a status without an {@code HttpStatus} constant,
     * such as nginx's 499. The response must be adapted like any other 4xx response instead of surfacing as a 500.
     */
    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void aStatusWithoutAnHttpStatusConstantIsUnauthorized(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginUnauthorized(httpClient.toBlocking(), USER_UNKNOWN_STATUS, PASSWORD);
            assertSingleFailure(app, AuthenticationFailureReason.UNKNOWN);
        }
    }

    /**
     * The 401 body must not tell a wrong password from a locked account, a required verification or a rejection
     * without a token error response: a client without the client secret would otherwise learn what the provider
     * answered.
     */
    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void everyRejectionIsAnsweredWithTheSameBody(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            String wrongPassword = assertLoginUnauthorized(client, USER, WRONG_PASSWORD);
            assertEquals(wrongPassword, assertLoginUnauthorized(client, USER_UNKNOWN_ERROR_CODE, PASSWORD));
            assertEquals(wrongPassword, assertLoginUnauthorized(client, USER_FORBIDDEN, PASSWORD));
            assertEquals(wrongPassword, assertLoginUnauthorized(client, USER_MALFORMED_BODY, PASSWORD));
            assertEquals(wrongPassword, assertLoginUnauthorized(client, USER_UNKNOWN_STATUS, PASSWORD));
        }
    }

    /**
     * With the default {@code ANY} strategy a rejection of the password grant lets the next provider in precedence
     * order decide, and when none authenticates the user the login is answered with 401, not with the rejection as
     * a 500.
     */
    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void withTheAnyStrategyARejectionLetsTheNextProviderDecide(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer), MAPPER_SUCCEEDS, true);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            MockProviderController provider = authServer.getApplicationContext().getBean(MockProviderController.class);
            LoginFailedEvents events = app.getApplicationContext().getBean(LoginFailedEvents.class);

            String accessToken = login(client, LOCAL_USER, LOCAL_PASSWORD);
            assertEquals(1, provider.tokenRequests.get(), "the password grant provider must be consulted first");
            assertEquals(LOCAL_USER, client.retrieve(HttpRequest.GET("/").bearerAuth(accessToken)));
            assertTrue(events.responses.isEmpty());

            assertLoginUnauthorized(client, LOCAL_USER, WRONG_PASSWORD);
            assertEquals(2, provider.tokenRequests.get());
            assertEquals(1, events.responses.size());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void providerOutageIsAServerErrorNotAnAuthenticationFailure(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), USER_OUTAGE, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "a provider outage must not be published as a failed login");
        }
    }

    /**
     * Valid credentials are rejected while the provider throttles the application. Counting that as a failed login
     * would feed account lockout logic listening to {@link LoginFailedEvent}.
     */
    @ParameterizedTest
    @ValueSource(strings = {OPENID, OAUTH})
    void rateLimitedTokenEndpointIsAServerErrorNotAnAuthenticationFailure(String clientType) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), USER_THROTTLED, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "a rate limited token endpoint must not be published as a failed login");
        }
    }

    /**
     * Some providers signal a transient condition with a 4xx status, for example {@code 400 temporarily_unavailable}.
     * Like a 429, it is not a verdict on the credentials.
     */
    @ParameterizedTest
    @CsvSource({
        OPENID + "," + USER_TEMPORARILY_UNAVAILABLE,
        OAUTH + "," + USER_TEMPORARILY_UNAVAILABLE,
        OPENID + "," + USER_SERVER_ERROR_CODE,
        OAUTH + "," + USER_SERVER_ERROR_CODE})
    void transientErrorCodeIsAServerErrorNotAnAuthenticationFailure(String clientType, String username) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer));
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), username, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "a transient condition of the provider must not be published as a failed login");
        }
    }

    /**
     * The token endpoint accepted the credentials. A 4xx response of a dependency the authentication mapper, or the
     * OpenID token response validator, calls is not a verdict on the credentials and must not become a failed login,
     * whether the error is emitted or thrown.
     */
    @ParameterizedTest
    @CsvSource({
        OPENID + "," + MAPPER_EMITS,
        OPENID + "," + MAPPER_THROWS,
        OPENID + "," + VALIDATOR_THROWS,
        OAUTH + "," + MAPPER_EMITS,
        OAUTH + "," + MAPPER_THROWS})
    void mapperErrorIsAServerErrorNotAnAuthenticationFailure(String clientType, String mapperError) {
        try (EmbeddedServer authServer = startAuthServer();
             EmbeddedServer app = startApp(clientType, issuer(authServer), mapperError);
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), USER, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "an error of the authentication mapper must not be published as a failed login");
        }
    }

    @Test
    void unreachableTokenEndpointIsAServerErrorNotAnAuthenticationFailure() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        try (EmbeddedServer app = startApp(OAUTH, "http://localhost:" + closedPort + "/oauth2/default");
             HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
            assertLoginServerError(httpClient.toBlocking(), USER, PASSWORD);
            assertTrue(app.getApplicationContext().getBean(LoginFailedEvents.class).responses.isEmpty(),
                "an unreachable token endpoint must not be published as a failed login");
        }
    }

    private static EmbeddedServer startAuthServer() {
        return ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER));
    }

    private static EmbeddedServer startApp(String clientType, String issuer) {
        return startApp(clientType, issuer, MAPPER_SUCCEEDS);
    }

    /**
     * @param clientType {@value #OPENID} for a client configured with the issuer (discovery), {@value #OAUTH} for a
     *                   client configured with the token endpoint URL only
     * @param issuer The issuer of the provider, under which its token endpoint is {@code /token}
     * @param mapperError {@value #MAPPER_SUCCEEDS}, {@value #MAPPER_EMITS} an error, {@value #MAPPER_THROWS} it, or
     *                    {@value #VALIDATOR_THROWS} (OpenID only: the token response validator throws)
     */
    private static EmbeddedServer startApp(String clientType, String issuer, String mapperError) {
        return startApp(clientType, issuer, mapperError, false);
    }

    /**
     * @param localProvider Whether to register a local authentication provider of lowest precedence, which accepts
     *                      {@value #LOCAL_USER}
     */
    private static EmbeddedServer startApp(String clientType, String issuer, String mapperError, boolean localProvider) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", APP);
        properties.put(CLIENT_TYPE_PROPERTY, clientType);
        properties.put(MAPPER_ERROR_PROPERTY, mapperError);
        properties.put(LOCAL_PROVIDER_PROPERTY, localProvider);
        properties.put("micronaut.security.authentication", "bearer");
        properties.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret");
        properties.put("micronaut.security.oauth2.clients." + CLIENT_NAME + ".grant-type", "password");
        properties.put("micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-id", CLIENT_ID);
        properties.put("micronaut.security.oauth2.clients." + CLIENT_NAME + ".client-secret", CLIENT_SECRET);
        if (OPENID.equals(clientType)) {
            properties.put("micronaut.security.oauth2.clients." + CLIENT_NAME + ".openid.issuer", issuer);
        } else {
            properties.put("micronaut.security.oauth2.clients." + CLIENT_NAME + ".token.url", tokenUrl(issuer));
        }
        return ApplicationContext.run(EmbeddedServer.class, properties);
    }

    private static String issuer(EmbeddedServer authServer) {
        return "http://localhost:" + authServer.getPort() + "/oauth2/default";
    }

    private static String tokenUrl(String issuer) {
        return issuer + "/token";
    }

    private static String login(BlockingHttpClient client, String username, String password) {
        Map<String, Object> body = client.retrieve(loginRequest(username, password), Argument.mapOf(String.class, Object.class));
        Object accessToken = body.get("access_token");
        assertNotNull(accessToken, "login response must contain an access token");
        return accessToken.toString();
    }

    /**
     * @return The body of the 401 response
     */
    private static String assertLoginUnauthorized(BlockingHttpClient client, String username, String password) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(loginRequest(username, password), String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
        assertResponseLeaksNothing(e, password);
        return e.getResponse().getBody(String.class).orElse("");
    }

    private static void assertSingleFailure(EmbeddedServer app, AuthenticationFailureReason reason) {
        List<AuthenticationResponse> responses = app.getApplicationContext().getBean(LoginFailedEvents.class).responses;
        assertEquals(1, responses.size(), () -> "one LoginFailedEvent expected, got " + responses);
        assertEquals(reason, assertInstanceOf(AuthenticationFailed.class, responses.get(0)).getReason());
    }

    private static ListAppender<ILoggingEvent> adapterLog(Level level) {
        Logger logger = (Logger) LoggerFactory.getLogger(ThrowableAuthenticationResponseAdapter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(level);
        return appender;
    }

    private static void detach(ListAppender<ILoggingEvent> appender) {
        Logger logger = (Logger) LoggerFactory.getLogger(ThrowableAuthenticationResponseAdapter.class);
        logger.setLevel(null);
        logger.detachAppender(appender);
    }

    private static void assertLoginServerError(BlockingHttpClient client, String username, String password) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(loginRequest(username, password), String.class));
        assertTrue(e.getStatus().getCode() >= 500, () -> "expected a server error but got " + e.getStatus());
        assertResponseLeaksNothing(e, password);
    }

    private static void assertResponseLeaksNothing(HttpClientResponseException e, String password) {
        String body = e.getResponse().getBody(String.class).orElse("");
        assertFalse(body.contains(password), "the response must not echo the password");
        assertFalse(body.contains(CLIENT_SECRET), "the response must not echo the client secret");
        assertFalse(body.contains(ERROR_DESCRIPTION), "the response must not relay the provider's error description");
    }

    private static HttpRequest<?> loginRequest(String username, String password) {
        return HttpRequest.POST("/login", new UsernamePasswordCredentials(username, password));
    }

    @Requires(property = "spec.name", value = APP)
    @Singleton
    static class LoginFailedEvents implements ApplicationEventListener<LoginFailedEvent> {
        final List<AuthenticationResponse> responses = new CopyOnWriteArrayList<>();

        @Override
        public void onApplicationEvent(LoginFailedEvent event) {
            responses.add((AuthenticationResponse) event.getSource());
        }
    }

    /**
     * Local provider of lowest precedence, consulted after the password grant provider.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = LOCAL_PROVIDER_PROPERTY, value = "true")
    @Singleton
    static class LocalProvider implements ReactiveAuthenticationProvider<HttpRequest<?>, String, String> {
        @Override
        @NonNull
        public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> requestContext,
                                                              @NonNull AuthenticationRequest<String, String> authenticationRequest) {
            return Mono.just(LOCAL_USER.equals(authenticationRequest.getIdentity()) && LOCAL_PASSWORD.equals(authenticationRequest.getSecret())
                ? AuthenticationResponse.success(LOCAL_USER)
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH));
        }

        @Override
        public int getOrder() {
            return LOWEST_PRECEDENCE;
        }
    }

    @Requires(property = "spec.name", value = APP)
    @Requires(property = CLIENT_TYPE_PROPERTY, value = OAUTH)
    @Named(CLIENT_NAME)
    @Singleton
    static class OauthMapper implements OauthAuthenticationMapper {
        private final String error;

        OauthMapper(@Property(name = MAPPER_ERROR_PROPERTY) String error) {
            this.error = error;
        }

        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return MAPPER_SUCCEEDS.equals(error) ? Mono.just(AuthenticationResponse.success("oauth-user")) : dependencyNotFound(error);
        }
    }

    /**
     * OpenID mapper which calls a dependency that answers 404.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = CLIENT_TYPE_PROPERTY, value = OPENID)
    @Requires(property = MAPPER_ERROR_PROPERTY, pattern = MAPPER_EMITS + "|" + MAPPER_THROWS)
    @Named(CLIENT_NAME)
    @Singleton
    static class FailingOpenIdMapper implements OpenIdAuthenticationMapper {
        private final String error;

        FailingOpenIdMapper(@Property(name = MAPPER_ERROR_PROPERTY) String error) {
            this.error = error;
        }

        @Override
        @NonNull
        public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                              OpenIdTokenResponse tokenResponse,
                                                                              OpenIdClaims openIdClaims,
                                                                              @Nullable State state) {
            return dependencyNotFound(error);
        }
    }

    /**
     * OpenID token response validator which calls a dependency that answers 404 and throws synchronously.
     */
    @Requires(property = "spec.name", value = APP)
    @Requires(property = CLIENT_TYPE_PROPERTY, value = OPENID)
    @Requires(property = MAPPER_ERROR_PROPERTY, value = VALIDATOR_THROWS)
    @Primary
    @Singleton
    static class ThrowingTokenResponseValidator implements ReactiveOpenIdTokenResponseValidator<JWT> {
        @Override
        @NonNull
        public Publisher<JWT> validate(@NonNull OauthClientConfiguration clientConfiguration,
                                       @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                       @NonNull OpenIdTokenResponse openIdTokenResponse,
                                       @Nullable String nonce) {
            throw new HttpClientResponseException("key service answered 404", HttpResponse.notFound());
        }
    }

    /**
     * @param mode {@value #MAPPER_EMITS} to return an error publisher, {@value #MAPPER_THROWS} to throw
     * @return An error publisher
     */
    private static Publisher<AuthenticationResponse> dependencyNotFound(String mode) {
        HttpClientResponseException e = new HttpClientResponseException("role service answered 404", HttpResponse.notFound());
        if (MAPPER_THROWS.equals(mode)) {
            throw e;
        }
        return Mono.error(e);
    }

    @Requires(property = "spec.name", value = APP)
    @Controller("/")
    static class HomeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Authentication authentication) {
            return authentication.getName();
        }
    }

    /**
     * The signing key of the mock provider. Generated once for the test class: every test starts its own provider.
     */
    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Singleton
    static class ProviderKey {
        private static final RSAKey KEY = generate();

        final RSAKey key = KEY;

        private static RSAKey generate() {
            try {
                return new RSAKeyGenerator(2048).keyID("test-key").generate();
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Controller("/oauth2/default")
    static class MockProviderController {
        final AtomicInteger tokenRequests = new AtomicInteger();
        private final ProviderKey providerKey;
        private final EmbeddedServer embeddedServer;

        MockProviderController(ProviderKey providerKey, EmbeddedServer embeddedServer) {
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
            tokenRequests.incrementAndGet();
            if (!"password".equals(grantType) || !PASSWORD.equals(password)) {
                return tokenError(HttpStatus.BAD_REQUEST, "invalid_grant");
            }
            return switch (username) {
                case USER_INVALID_CLIENT -> tokenError(HttpStatus.UNAUTHORIZED, "invalid_client");
                case USER_UNKNOWN_ERROR_CODE -> tokenError(HttpStatus.BAD_REQUEST, "account_locked");
                case USER_TEMPORARILY_UNAVAILABLE -> tokenError(HttpStatus.BAD_REQUEST, "temporarily_unavailable");
                case USER_SERVER_ERROR_CODE -> tokenError(HttpStatus.BAD_REQUEST, "server_error");
                case USER_NOT_FOUND -> HttpResponse.<String>status(HttpStatus.NOT_FOUND).body("Not Found").contentType(MediaType.TEXT_PLAIN_TYPE);
                case USER_MALFORMED_BODY -> HttpResponse.<String>status(HttpStatus.BAD_REQUEST).body("{\"error\":").contentType(MediaType.APPLICATION_JSON_TYPE);
                case USER_EMPTY_BODY -> HttpResponse.<String>status(HttpStatus.BAD_REQUEST).body("").contentType(MediaType.APPLICATION_JSON_TYPE);
                case USER_NON_STRING_ERROR -> HttpResponse.<String>status(HttpStatus.BAD_REQUEST).body("{\"error\":{\"code\":42},\"error_description\":\"" + ERROR_DESCRIPTION + "\"}").contentType(MediaType.APPLICATION_JSON_TYPE);
                case USER_UNKNOWN_STATUS -> HttpResponse.<String>status(499, "Client Closed Request").body("{\"error\":\"client_closed_request\",\"error_description\":\"" + ERROR_DESCRIPTION + "\"}").contentType(MediaType.APPLICATION_JSON_TYPE);
                case USER_FORBIDDEN -> HttpResponse.<String>status(HttpStatus.FORBIDDEN).body("Forbidden").contentType(MediaType.TEXT_PLAIN_TYPE);
                case USER_OUTAGE -> HttpResponse.<String>status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"error\":\"server_error\"}").contentType(MediaType.APPLICATION_JSON_TYPE);
                case USER_THROTTLED -> HttpResponse.<String>status(HttpStatus.TOO_MANY_REQUESTS).body("{\"error\":\"rate_limit_exceeded\"}").header(HttpHeaders.RETRY_AFTER, "60").contentType(MediaType.APPLICATION_JSON_TYPE);
                default -> tokenResponse(username);
            };
        }

        private static HttpResponse<String> tokenError(HttpStatus status, String error) {
            return HttpResponse.<String>status(status)
                .body("{\"error\":\"" + error + "\",\"error_description\":\"" + ERROR_DESCRIPTION + "\"}")
                .contentType(MediaType.APPLICATION_JSON_TYPE);
        }

        private HttpResponse<String> tokenResponse(String username) throws JOSEException {
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
