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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Adapts the error signal of a token request to an {@link AuthenticationResponse}: a failed authentication whose
 * reason is derived from the token endpoint's rejection of the grant.
 *
 * <p>A 4xx response of the token endpoint is the authorization server rejecting the grant
 * (<a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 section 5.2</a>, for example
 * {@code invalid_grant} for wrong credentials), so it is an authentication failure. Not every 4xx response is a
 * verdict on the credentials, though, and those which are not are propagated as errors, as a 5xx response, a
 * connection failure or an unparseable token response are:</p>
 * <ul>
 *     <li>The transient responses {@code 408 Request Timeout}, {@code 425 Too Early} and {@code 429 Too Many Requests},
 *     and a response whose error code is {@code temporarily_unavailable} or {@code server_error} whatever its status,
 *     since some providers and the proxies in front of them signal a transient condition with a 4xx status. Valid
 *     credentials are rejected while the provider is unavailable or throttles the application, so counting such a
 *     response as a failed login would feed account lockout logic.</li>
 *     <li>A response whose error code is {@code invalid_client}, {@code unauthorized_client},
 *     {@code unsupported_grant_type} or {@code invalid_request}, which per RFC 6749 section 5.2 rejects the client or
 *     the request rather than the resource owner's credentials, and the statuses {@code 404}, {@code 405}, {@code 407}
 *     and {@code 415}, which answer a token request sent to the wrong URL, through a proxy demanding authentication,
 *     or in a form the endpoint does not accept. These are never caused by the user, so they are logged at
 *     {@code WARN}: answered as a failed login they would surface as a 401 for every user and feed the lockout
 *     counter of each of them, for example while the client secret is rotated.</li>
 * </ul>
 * <p>{@link #isRejection(Throwable)} tells a rejection of the credentials from the other failures, so that a password
 * grant provider can resume the error signal of the token request with this adapter for a rejection and propagate any
 * other failure. Errors of the token response validation or of the authentication mapper happen after the token
 * request succeeded and are not adapted.</p>
 *
 * <p>Only the HTTP status and the error code of the response are logged, at {@code DEBUG} for a rejection: the
 * response body may carry an {@code error_description} written by the provider, and the request carries the user's
 * password and the client secret. The body is only parsed when its content type is JSON or absent, so that a
 * non-JSON rejection does not reach the HTTP client's decoder. The failure message of the adapter is the same for
 * every rejection, so that the {@code 401} body does not tell a wrong password from an account the provider locked or
 * a verification it demands; the {@link #getReason() reason} still tells them apart for the listeners of a
 * {@link io.micronaut.security.event.LoginFailedEvent}.</p>
 *
 * @author Sergio del Amo
 * @since 5.5.2
 */
@Internal
public final class ThrowableAuthenticationResponseAdapter extends AuthenticationFailed {

    private static final Logger LOG = LoggerFactory.getLogger(ThrowableAuthenticationResponseAdapter.class);
    private static final int TOO_EARLY = 425;
    private static final int PROXY_AUTHENTICATION_REQUIRED = 407;
    private static final int MAX_ERROR_CODE_LENGTH = 64;
    private static final String UNKNOWN_ERROR_CODE = "unknown";

    /**
     * The failure message of every rejection, the one of a wrong password with a local authentication provider.
     */
    private static final String MESSAGE = new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        .getMessage()
        .orElseThrow();

    private static final Set<Integer> TRANSIENT_STATUS_CODES = Set.of(
        HttpStatus.REQUEST_TIMEOUT.getCode(),
        TOO_EARLY,
        HttpStatus.TOO_MANY_REQUESTS.getCode());

    private static final Set<Integer> MISCONFIGURATION_STATUS_CODES = Set.of(
        HttpStatus.NOT_FOUND.getCode(),
        HttpStatus.METHOD_NOT_ALLOWED.getCode(),
        PROXY_AUTHENTICATION_REQUIRED,
        HttpStatus.UNSUPPORTED_MEDIA_TYPE.getCode());

    /**
     * Error codes with which a provider signals a transient condition: {@code temporarily_unavailable} and
     * {@code server_error} of RFC 6749 section 4.1.2.1, which some providers answer with a 4xx status.
     */
    private static final Set<String> TRANSIENT_ERROR_CODES = Set.of("temporarily_unavailable", "server_error");

    /**
     * Error codes of RFC 6749 section 5.2 which reject the client or the request, never the resource owner's
     * credentials.
     */
    private static final Set<String> CLIENT_ERROR_CODES = Set.of(
        TokenError.INVALID_CLIENT.toString(),
        TokenError.UNAUTHORIZED_CLIENT.toString(),
        TokenError.UNSUPPORTED_GRANT_TYPE.toString(),
        TokenError.INVALID_REQUEST.toString());

    /**
     * @param throwable The error signal of the token request, for which {@link #isRejection(Throwable)} is {@code true}
     * @param clientName The name of the OAuth 2.0 client whose token endpoint was called
     * @throws IllegalArgumentException If the throwable is not the token endpoint rejecting the grant
     */
    public ThrowableAuthenticationResponseAdapter(@NonNull Throwable throwable, @NonNull String clientName) {
        this(rejection(throwable, clientName), clientName);
    }

    private ThrowableAuthenticationResponseAdapter(@NonNull TokenRequestFailure rejection, @NonNull String clientName) {
        super(failureReason(rejection, clientName));
    }

    /**
     * @param throwable The error signal of the token request
     * @return Whether the throwable is the token endpoint rejecting the credentials: a 4xx response other than the
     * transient ones, the ones rejecting the client or the request, and the ones answering a misdirected request
     */
    public static boolean isRejection(@NonNull Throwable throwable) {
        TokenRequestFailure failure = TokenRequestFailure.of(throwable);
        return failure != null && failure.kind() == Kind.REJECTION;
    }

    /**
     * Maps the error signal of the token request: the token endpoint rejecting the credentials is a failed
     * authentication, any other failure is propagated.
     *
     * @param throwable The error signal of the token request
     * @param clientConfiguration The configuration of the client whose token request failed
     * @return A failed authentication for a rejection, otherwise an error publisher carrying the throwable
     */
    public static Publisher<AuthenticationResponse> onTokenRequestError(Throwable throwable, OauthClientConfiguration clientConfiguration) {
        TokenRequestFailure failure = TokenRequestFailure.of(throwable);
        if (failure == null) {
            return Mono.error(throwable);
        }
        return switch (failure.kind()) {
            case REJECTION -> Mono.just(new ThrowableAuthenticationResponseAdapter(failure, clientConfiguration.getName()));
            case TRANSIENT -> {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Token endpoint of OAuth 2.0 client [{}] answered the password grant with HTTP status {} and error code [{}], a transient condition of the provider which is not a verdict on the credentials",
                        clientConfiguration.getName(), failure.statusCode(), failure.errorCodeOrUnknown());
                }
                yield Mono.error(throwable);
            }
            case MISCONFIGURATION -> {
                LOG.warn("Token endpoint of OAuth 2.0 client [{}] answered the password grant with HTTP status {} and error code [{}], which rejects the client or the request rather than the user's credentials. Check the client configuration",
                    clientConfiguration.getName(), failure.statusCode(), failure.errorCodeOrUnknown());
                yield Mono.error(throwable);
            }
        };
    }

    /**
     * The message is the same for every rejection, so that the 401 body does not relay the kind of rejection.
     */
    @Override
    protected String createMessage(AuthenticationFailureReason authenticationFailure) {
        return MESSAGE;
    }

    @NonNull
    private static TokenRequestFailure rejection(@NonNull Throwable throwable, @NonNull String clientName) {
        TokenRequestFailure failure = TokenRequestFailure.of(throwable);
        if (failure == null || failure.kind() != Kind.REJECTION) {
            throw new IllegalArgumentException("The token endpoint of OAuth 2.0 client [" + clientName + "] did not reject the grant", throwable);
        }
        return failure;
    }

    /**
     * Logs the rejection and derives the failure reason from it.
     *
     * @param rejection The rejection of the credentials
     * @param clientName The name of the OAuth 2.0 client whose token endpoint was called
     * @return {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH} for an {@code invalid_grant} error code,
     * otherwise {@link AuthenticationFailureReason#UNKNOWN}
     */
    @NonNull
    private static AuthenticationFailureReason failureReason(@NonNull TokenRequestFailure rejection, @NonNull String clientName) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Token endpoint of OAuth 2.0 client [{}] rejected the password grant with HTTP status {} and error code [{}]",
                clientName, rejection.statusCode(), rejection.errorCodeOrUnknown());
        }
        return TokenError.INVALID_GRANT.toString().equals(rejection.errorCode())
            ? AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH
            : AuthenticationFailureReason.UNKNOWN;
    }

    /**
     * Reads the error code of the token error response as a {@link GenericTokenErrorResponse}, so that error codes
     * providers add to those of RFC 6749 are reported too. The body is only parsed when its content type is JSON
     * or absent. The value is only accepted if it is an error code as RFC 6749 section 5.2 defines it, a short
     * string of printable ASCII characters other than {@code "} and {@code \\}; anything else, for example free text
     * or several lines, is not written to the log.
     *
     * @param response The error response of the token endpoint
     * @return The error code of the response, or {@code null} if the body is not a token error response whose
     * {@code error} member holds an error code
     */
    @Nullable
    private static String errorCode(@NonNull HttpResponse<?> response) {
        if (!response.getContentType().map(ThrowableAuthenticationResponseAdapter::isJson).orElse(true)) {
            return null;
        }
        try {
            return response.getBody(GenericTokenErrorResponse.class)
                .map(GenericTokenErrorResponse::error)
                .filter(ThrowableAuthenticationResponseAdapter::isErrorCode)
                .orElse(null);
        } catch (RuntimeException ignored) {
            // The body is not a token error response. The response stands regardless of its body.
            return null;
        }
    }

    private static boolean isJson(@NonNull MediaType contentType) {
        return MediaType.APPLICATION_JSON_TYPE.getType().equalsIgnoreCase(contentType.getType())
            && (MediaType.APPLICATION_JSON_TYPE.getSubtype().equalsIgnoreCase(contentType.getSubtype())
                || contentType.getSubtype().toLowerCase().endsWith("+json"));
    }

    private static boolean isErrorCode(@NonNull String value) {
        if (value.isEmpty() || value.length() > MAX_ERROR_CODE_LENGTH) {
            return false;
        }
        return value.chars().allMatch(c -> c >= 0x20 && c <= 0x7E && c != '"' && c != '\\');
    }

    /**
     * What a 4xx response of the token endpoint means.
     */
    private enum Kind {
        /** The token endpoint rejected the credentials. */
        REJECTION,
        /** The provider is unavailable or throttles the application. */
        TRANSIENT,
        /** The token endpoint rejected the client or the request, or the request did not reach a token endpoint. */
        MISCONFIGURATION
    }

    /**
     * A 4xx response of the token endpoint.
     *
     * @param statusCode The HTTP status code
     * @param errorCode The error code of the body, if it is a token error response
     * @param kind What the response means
     */
    private record TokenRequestFailure(int statusCode, @Nullable String errorCode, @NonNull Kind kind) {

        /**
         * @param throwable The error signal of the token request
         * @return The 4xx response of the token endpoint, or {@code null} if the throwable is not one
         */
        @Nullable
        static TokenRequestFailure of(@NonNull Throwable throwable) {
            if (!(throwable instanceof HttpClientResponseException e)) {
                return null;
            }
            // code() rather than getStatus(): the latter throws for a status without an HttpStatus constant,
            // such as the 460 and 463 of a load balancer or the 494 to 499 of nginx.
            int statusCode = e.code();
            if (statusCode < 400 || statusCode >= 500) {
                return null;
            }
            if (TRANSIENT_STATUS_CODES.contains(statusCode)) {
                return new TokenRequestFailure(statusCode, null, Kind.TRANSIENT);
            }
            if (MISCONFIGURATION_STATUS_CODES.contains(statusCode)) {
                return new TokenRequestFailure(statusCode, null, Kind.MISCONFIGURATION);
            }
            String errorCode = ThrowableAuthenticationResponseAdapter.errorCode(e.getResponse());
            if (errorCode != null && TRANSIENT_ERROR_CODES.contains(errorCode)) {
                return new TokenRequestFailure(statusCode, errorCode, Kind.TRANSIENT);
            }
            if (errorCode != null && CLIENT_ERROR_CODES.contains(errorCode)) {
                return new TokenRequestFailure(statusCode, errorCode, Kind.MISCONFIGURATION);
            }
            return new TokenRequestFailure(statusCode, errorCode, Kind.REJECTION);
        }

        @NonNull
        String errorCodeOrUnknown() {
            return errorCode == null ? UNKNOWN_ERROR_CODE : errorCode;
        }
    }
}
