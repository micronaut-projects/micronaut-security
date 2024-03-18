package io.micronaut.security.handlers

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.uri.UriBuilder
import io.micronaut.security.authentication.*
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.security.authentication.provider.HttpRequestReactiveAuthenticationProvider
import io.micronaut.security.config.RedirectConfiguration
import io.micronaut.security.config.RedirectService
import io.micronaut.security.errors.PriorToLoginPersistence
import io.micronaut.security.session.SessionAuthenticationModeCondition
import io.micronaut.security.session.SessionLoginHandler
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

@Property(name = "micronaut.security.authentication", value="session")
@Property(name = "micronaut.http.client.follow-redirects", value = StringUtils.FALSE)
@Property(name = "micronaut.security.redirect.login-failure", value="/security/login")
@Property(name = "spec.name", value="LoginFailedHttpRequestReactiveAuthenticationProviderSpec")
@MicronautTest
class LoginFailedHttpRequestReactiveAuthenticationProviderSpec extends Specification {

    @Shared
    @AutoCleanup
    @Inject
    @Client("/") HttpClient httpClient

    @Inject
    BeanContext beanContext

    void failureReasonIsNotLost() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        expect:
        beanContext.containsBean(SessionLoginHandlerReplacement)

        when:
        HttpResponse<?> response = client.exchange(HttpRequest.POST("/login", new UsernamePasswordCredentials("watson@example.com", "password")))
        String location = response.getHeaders().get(HttpHeaders.LOCATION)

        then:
        location
        "/security/login?reason=USER_DISABLED" == location
    }

    @Requires(property = "spec.name", value="LoginFailedHttpRequestReactiveAuthenticationProviderSpec")
    @Singleton
    static class AuthenticationProviderMock<B> implements HttpRequestReactiveAuthenticationProvider<B> {
        @Override
        @SingleResult
        @NonNull Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<B> requestContext, @NonNull AuthenticationRequest<String, String> authRequest) {
            return Mono.just(AuthenticationResponse.failure(AuthenticationFailureReason.USER_DISABLED))
        }
    }

    @Requires(property = "spec.name", value="LoginFailedHttpRequestReactiveAuthenticationProviderSpec")
    @Requires(condition = SessionAuthenticationModeCondition.class)
    @Singleton
    @Replaces(SessionLoginHandler.class)
    static class SessionLoginHandlerReplacement extends SessionLoginHandler {
        SessionLoginHandlerReplacement(RedirectConfiguration redirectConfiguration, SessionStore<Session> sessionStore, @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence, RedirectService redirectService) {
            super(redirectConfiguration, sessionStore,  priorToLoginPersistence, redirectService)
        }

        @Override
        MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
            return loginFailure(loginFailure, authenticationFailed)
                    .map(HttpResponse::seeOther)
                    .orElseGet(HttpResponse::unauthorized)
        }

        @NonNull
        static Optional<URI> loginFailure(@Nullable String loginFailure,
                                                 @NonNull AuthenticationResponse authenticationFailed) {
            if (loginFailure == null) {
                return Optional.empty()
            }
            UriBuilder uriBuilder = UriBuilder.of(loginFailure)
            if (authenticationFailed instanceof AuthenticationFailed) {
                AuthenticationFailed failure = (AuthenticationFailed) authenticationFailed
                if (failure.getReason() == AuthenticationFailureReason.USER_DISABLED) {
                    uriBuilder = uriBuilder.queryParam("reason", failure.getReason())
                }
            }
            Optional.of(uriBuilder.build())
        }
    }
}