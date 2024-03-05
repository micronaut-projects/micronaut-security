package io.micronaut.security.token

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.reader.HttpHeaderTokenReader
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono;
import spock.lang.Specification;

@Property(name = "spec.name", value = "TokenAuthenticationFetcherSpec")
@MicronautTest
class TokenAuthenticationFetcherSpec extends Specification {

    @Inject
    TokenAuthenticationFetcher tokenAuthenticationFetcher

    void "Beans of type TokenReader are evaluated in order"() {
        when: 'no token no authentication'
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        Authentication authentication = Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()

        then:
        !authentication

        when: 'valid token'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "xxx")
        authentication = Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()

        then:
        authentication
        "bar" == authentication.name

        when: 'X-API-TOKEN is not valid while Authorization token is valid, the latter is used to authenticate'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "zzz")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")
        authentication = Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()

        then:
        authentication
        "foo" == authentication.name

        when: 'Two valid tokens, the TokenReader with highest order should take precedence'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "xxx")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")
        authentication = Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()

        then:
        authentication
        "bar" == authentication.name
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherSpec")
    @Singleton
    static class ApiTokenReader extends HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null
        }

        @Override
        Optional<String> findToken(HttpRequest<?> request) {
            Optional<String> response = super.findToken(request)
            sleep(2_000)
            return response
        }

        @Override
        int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }

        @Override
        protected String getHeaderName() {
            return "X-API-KEY"
        }
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherSpec")
    @Singleton
    static class ApiKeyTokenValidator implements TokenValidator<HttpRequest<?>> {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            if (token.equals("xxx")) {
                return Publishers.just(Authentication.build("bar"))
            }
            if (token.equals("yyy")) {
                return Publishers.just(Authentication.build("foo"))
            }
            return Publishers.empty()
        }
    }
}
