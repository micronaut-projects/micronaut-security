package io.micronaut.security.filters

import io.micronaut.context.annotation.Requires
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.token.TokenAuthenticationFetcher
import io.micronaut.security.token.reader.HttpHeaderTokenReader
import io.micronaut.security.token.validator.TokenValidator
import jakarta.inject.Singleton
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

import java.util.concurrent.atomic.AtomicInteger

/**
 * A {@link TokenValidator} failure (for example a JWKS fetch failing) must not turn into a 500 nor prevent the
 * remaining {@link AuthenticationFetcher} beans (such as Basic auth) from authenticating the request.
 */
class TokenValidatorErrorSecurityFilterSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'TokenValidatorErrorSecurityFilterSpec'
    }

    void setup() {
        getBean(ErroringTokenValidator).invocations.set(0)
    }

    void "the fetchers are present"() {
        expect:
        getBean(TokenAuthenticationFetcher)
        getBean(BasicAuthAuthenticationFetcher)
    }

    void "when the only token validator errors, basic auth can still authenticate the request"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/token-validator-error')
                .header("X-API-KEY", "some-api-key")
                .basicAuth("user", "password")

        when:
        HttpResponse<String> response = client.exchange(request, String)

        then:
        response.status() == HttpStatus.OK
        response.body() == "user"
        getBean(ErroringTokenValidator).invocations.get() == 1
    }

    void "when the only token validator errors and nothing else authenticates, the response is 401 not 500"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/token-validator-error')
                .header("X-API-KEY", "some-api-key")

        when:
        client.exchange(request, String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
        getBean(ErroringTokenValidator).invocations.get() == 1
    }

    void "when the only token validator errors for a bearer token, the response is 401 not 500"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/token-validator-error').bearerAuth("some-bearer-token")

        when:
        client.exchange(request, String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
        getBean(ErroringTokenValidator).invocations.get() == 1
    }

    @Requires(property = "spec.name", value = "TokenValidatorErrorSecurityFilterSpec")
    @Controller("/token-validator-error")
    static class TokenValidatorErrorController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Authentication authentication) {
            authentication.name
        }
    }

    @Requires(property = "spec.name", value = "TokenValidatorErrorSecurityFilterSpec")
    @Singleton
    static class ApiKeyTokenReader extends HttpHeaderTokenReader {

        @Override
        protected String getPrefix() {
            null
        }

        @Override
        protected String getHeaderName() {
            "X-API-KEY"
        }

        @Override
        int getOrder() {
            Ordered.HIGHEST_PRECEDENCE
        }
    }

    @Requires(property = "spec.name", value = "TokenValidatorErrorSecurityFilterSpec")
    @Singleton
    static class ErroringTokenValidator implements TokenValidator<HttpRequest<?>> {
        final AtomicInteger invocations = new AtomicInteger()

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            invocations.incrementAndGet()
            Mono.error(new IllegalStateException("JWKS unavailable"))
        }
    }

    @Requires(property = "spec.name", value = "TokenValidatorErrorSecurityFilterSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', 'password')])
        }
    }
}
