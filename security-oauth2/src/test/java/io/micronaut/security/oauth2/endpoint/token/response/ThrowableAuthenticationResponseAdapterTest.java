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
package io.micronaut.security.oauth2.endpoint.token.response;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThrowableAuthenticationResponseAdapterTest {

    private static final String CLIENT_NAME = "keycloak";
    private static final String ERROR_DESCRIPTION = "The user account has been locked by an administrator";
    private static final OauthClientConfiguration CLIENT_CONFIGURATION = new OauthClientConfigurationProperties(CLIENT_NAME);

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 422, 499})
    void aNonTransient4xxIsARejection(int status) {
        assertTrue(ThrowableAuthenticationResponseAdapter.isRejection(response(status, "{}")));
    }

    @ParameterizedTest
    @ValueSource(ints = {408, 425, 429, 500, 502, 503, 302, 200})
    void transientAndNon4xxResponsesAreNotRejections(int status) {
        assertFalse(ThrowableAuthenticationResponseAdapter.isRejection(response(status, "{}")));
    }

    /**
     * Some providers signal a transient condition with a 4xx status, for example Microsoft's identity platform
     * answers {@code temporarily_unavailable} with 400, and proxies in front of a provider throttle with 400 or 403.
     */
    @ParameterizedTest
    @CsvSource({"400,temporarily_unavailable", "400,server_error", "403,temporarily_unavailable", "503,temporarily_unavailable"})
    void aTransientErrorCodeIsNotARejection(int status, String errorCode) {
        assertFalse(ThrowableAuthenticationResponseAdapter.isRejection(response(status, tokenError(errorCode))));
    }

    /**
     * RFC 6749 section 5.2: these error codes reject the client or the request, not the resource owner's credentials.
     */
    @ParameterizedTest
    @CsvSource({"401,invalid_client", "400,unauthorized_client", "400,unsupported_grant_type", "400,invalid_request"})
    void anErrorCodeRejectingTheClientIsNotARejection(int status, String errorCode) {
        assertFalse(ThrowableAuthenticationResponseAdapter.isRejection(response(status, tokenError(errorCode))));
    }

    /**
     * A wrong token URL, an egress proxy demanding authentication or a form the endpoint does not accept.
     */
    @ParameterizedTest
    @ValueSource(ints = {404, 405, 407, 415})
    void aMisdirectedRequestIsNotARejection(int status) {
        assertFalse(ThrowableAuthenticationResponseAdapter.isRejection(response(status, tokenError("invalid_grant"))));
    }

    @Test
    void aFailureWhichIsNotAResponseIsNotARejection() {
        assertFalse(ThrowableAuthenticationResponseAdapter.isRejection(new IOException("Connection refused")));
    }

    @Test
    void invalidGrantIsCredentialsDoNotMatch() {
        HttpClientResponseException rejection = response(400, tokenError("invalid_grant"));

        ThrowableAuthenticationResponseAdapter adapter = new ThrowableAuthenticationResponseAdapter(rejection, CLIENT_NAME);

        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, adapter.getReason());
        assertFalse(adapter.isAuthenticated());
        assertTrue(adapter.getAuthentication().isEmpty());
        assertTrue(adapter.getMessage().isPresent());
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid_scope", "account_locked", "interaction_required", "mfa_required"})
    void otherErrorCodesAreAnUnknownFailure(String errorCode) {
        ThrowableAuthenticationResponseAdapter adapter = new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError(errorCode)), CLIENT_NAME);

        assertEquals(AuthenticationFailureReason.UNKNOWN, adapter.getReason());
        assertTrue(adapter.getAuthentication().isEmpty());
    }

    @Test
    void aRejectionWithoutATokenErrorBodyIsAnUnknownFailure() {
        ThrowableAuthenticationResponseAdapter adapter = new ThrowableAuthenticationResponseAdapter(
            response(403, "<html><body>Forbidden</body></html>", MediaType.TEXT_HTML_TYPE), CLIENT_NAME);

        assertEquals(AuthenticationFailureReason.UNKNOWN, adapter.getReason());
    }

    /**
     * {@code HttpClientResponseException#getStatus()} throws for a status without an {@code HttpStatus} constant,
     * such as nginx's 499. The response must still be adapted rather than turned into an
     * {@code IllegalArgumentException}.
     */
    @Test
    void aStatusWithoutAnHttpStatusConstantIsARejection() {
        HttpClientResponseException rejection = response(499, tokenError("client_closed_request"));
        assertThrows(IllegalArgumentException.class, rejection::getStatus, "the test needs a status without a constant");

        ThrowableAuthenticationResponseAdapter adapter = new ThrowableAuthenticationResponseAdapter(rejection, CLIENT_NAME);

        assertEquals(AuthenticationFailureReason.UNKNOWN, adapter.getReason());
        assertTrue(ThrowableAuthenticationResponseAdapter.isRejection(rejection));
        AuthenticationResponse response = Mono.from(ThrowableAuthenticationResponseAdapter.onTokenRequestError(rejection, CLIENT_CONFIGURATION)).block();
        assertSame(ThrowableAuthenticationResponseAdapter.class, response.getClass());
    }

    /**
     * The 401 body must not tell a wrong password from a locked account or a required verification.
     */
    @Test
    void theMessageIsTheSameForEveryRejection() {
        String expected = new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH).getMessage().orElseThrow();

        assertEquals(expected, new ThrowableAuthenticationResponseAdapter(response(400, tokenError("invalid_grant")), CLIENT_NAME).getMessage().orElseThrow());
        assertEquals(expected, new ThrowableAuthenticationResponseAdapter(response(400, tokenError("account_locked")), CLIENT_NAME).getMessage().orElseThrow());
        assertEquals(expected, new ThrowableAuthenticationResponseAdapter(response(400, tokenError("interaction_required")), CLIENT_NAME).getMessage().orElseThrow());
        assertEquals(expected, new ThrowableAuthenticationResponseAdapter(response(403, "Forbidden", MediaType.TEXT_PLAIN_TYPE), CLIENT_NAME).getMessage().orElseThrow());
    }

    /**
     * A body declared as something other than JSON is not handed to the decoder, so its error code is not read.
     * A body without a content type is parsed, for providers which omit the header RFC 6749 requires.
     */
    @Test
    void onlyAJsonOrUntypedBodyIsParsed() {
        assertEquals(AuthenticationFailureReason.UNKNOWN, new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError("invalid_grant"), MediaType.TEXT_HTML_TYPE), CLIENT_NAME).getReason());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError("invalid_grant"), MediaType.APPLICATION_JSON_TYPE), CLIENT_NAME).getReason());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError("invalid_grant"), MediaType.of("application/problem+json")), CLIENT_NAME).getReason());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError("invalid_grant")), CLIENT_NAME).getReason());
        assertTrue(ThrowableAuthenticationResponseAdapter.isRejection(response(400, tokenError("invalid_client"), MediaType.TEXT_HTML_TYPE)),
            "an error code the decoder is not asked for cannot reject the client");
    }

    @Test
    void theErrorCodeIsLoggedAtDebugWithoutTheDescription() {
        List<ILoggingEvent> events = log(Level.DEBUG, () -> new ThrowableAuthenticationResponseAdapter(
            response(400, tokenError("account_locked")), CLIENT_NAME));

        assertEquals(1, events.size(), () -> "one DEBUG message expected, got " + events);
        String message = events.get(0).getFormattedMessage();
        assertEquals(Level.DEBUG, events.get(0).getLevel());
        assertTrue(message.contains("[" + CLIENT_NAME + "]"), message);
        assertTrue(message.contains("HTTP status 400 and error code [account_locked]"), message);
        assertFalse(message.contains(ERROR_DESCRIPTION), message);
    }

    @Test
    void anErrorMemberWhichIsNotAnErrorCodeIsNotLogged() {
        String freeText = "Invalid user credentials\nContact support \"now\"";
        List<ILoggingEvent> events = log(Level.DEBUG, () -> new ThrowableAuthenticationResponseAdapter(
            response(400, new GenericTokenErrorResponse(freeText, null, null)), CLIENT_NAME));

        assertEquals(1, events.size(), () -> "one DEBUG message expected, got " + events);
        String message = events.get(0).getFormattedMessage();
        assertTrue(message.contains("error code [unknown]"), message);
        assertFalse(message.contains("Contact support"), message);
    }

    /**
     * A rejection of the client is never caused by the user, so it is worth a WARN, which must not relay the error
     * description either.
     */
    @ParameterizedTest
    @CsvSource({"401,invalid_client", "400,unsupported_grant_type", "404,"})
    void aRejectionOfTheClientIsPropagatedAndLoggedAtWarn(int status, String errorCode) {
        HttpClientResponseException failure = response(status, tokenError(errorCode == null ? "not_found" : errorCode));

        List<ILoggingEvent> events = log(Level.WARN, () -> assertSame(failure, assertThrows(HttpClientResponseException.class,
            () -> Mono.from(ThrowableAuthenticationResponseAdapter.onTokenRequestError(failure, CLIENT_CONFIGURATION)).block())));

        assertEquals(1, events.size(), () -> "one WARN message expected, got " + events);
        String message = events.get(0).getFormattedMessage();
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertTrue(message.contains("[" + CLIENT_NAME + "]"), message);
        assertTrue(message.contains("HTTP status " + status + " and error code [" + (errorCode == null ? "unknown" : errorCode) + "]"), message);
        assertFalse(message.contains(ERROR_DESCRIPTION), message);
    }

    @ParameterizedTest
    @CsvSource({"400,temporarily_unavailable", "400,server_error", "429,rate_limit_exceeded"})
    void aTransientFailureIsPropagatedWithoutAWarning(int status, String errorCode) {
        HttpClientResponseException failure = response(status, tokenError(errorCode));

        List<ILoggingEvent> events = log(Level.WARN, () -> assertSame(failure, assertThrows(HttpClientResponseException.class,
            () -> Mono.from(ThrowableAuthenticationResponseAdapter.onTokenRequestError(failure, CLIENT_CONFIGURATION)).block())));

        assertTrue(events.isEmpty(), () -> "no WARN expected for a transient failure, got " + events);
    }

    @Test
    void aFailureWhichIsNotARejectionCannotBeAdapted() {
        HttpClientResponseException outage = response(503, tokenError("temporarily_unavailable"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> new ThrowableAuthenticationResponseAdapter(outage, CLIENT_NAME));

        assertSame(outage, e.getCause());
        assertThrows(IllegalArgumentException.class,
            () -> new ThrowableAuthenticationResponseAdapter(response(401, tokenError("invalid_client")), CLIENT_NAME));
        assertThrows(IllegalArgumentException.class,
            () -> new ThrowableAuthenticationResponseAdapter(response(400, tokenError("temporarily_unavailable")), CLIENT_NAME));
        assertThrows(IllegalArgumentException.class,
            () -> new ThrowableAuthenticationResponseAdapter(new IOException("Connection refused"), CLIENT_NAME));
    }

    private static GenericTokenErrorResponse tokenError(String errorCode) {
        return new GenericTokenErrorResponse(errorCode, ERROR_DESCRIPTION, null);
    }

    private static HttpClientResponseException response(int status, Object body) {
        return response(status, body, null);
    }

    private static HttpClientResponseException response(int status, Object body, MediaType contentType) {
        MutableHttpResponse<Object> response = HttpResponse.status(status, "Status " + status).body(body);
        if (contentType != null) {
            response.contentType(contentType);
        }
        return new HttpClientResponseException("Status " + status, response);
    }

    private static List<ILoggingEvent> log(Level level, Runnable runnable) {
        Logger logger = (Logger) LoggerFactory.getLogger(ThrowableAuthenticationResponseAdapter.class);
        Level previous = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(level);
        try {
            runnable.run();
        } finally {
            logger.setLevel(previous);
            logger.detachAppender(appender);
        }
        return appender.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(level)).toList();
    }
}
