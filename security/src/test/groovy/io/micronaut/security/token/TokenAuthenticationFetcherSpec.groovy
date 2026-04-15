package io.micronaut.security.token

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
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
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import spock.lang.Specification

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@Property(name = "spec.name", value = "TokenAuthenticationFetcherSpec")
@MicronautTest
class TokenAuthenticationFetcherSpec extends Specification {

    private static final String LOW_PRECEDENCE_VALIDATOR_LATCH = "low-precedence-validator-latch"

    @Inject
    TokenAuthenticationFetcher tokenAuthenticationFetcher

    void "beans of type TokenReader are evaluated in order"() {
        when: 'no token no authentication'
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        Authentication authentication = fetchAuthentication(request)

        then:
        !authentication

        when: 'valid token'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "xxx")
        authentication = fetchAuthentication(request)

        then:
        authentication
        "bar" == authentication.name

        when: 'X-API-TOKEN is not valid while Authorization token is valid, the latter is used to authenticate'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "zzz")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")
        authentication = fetchAuthentication(request)

        then:
        authentication
        "foo" == authentication.name

        when: 'Two valid tokens, the TokenReader with highest order should take precedence'
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "xxx")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")
        authentication = fetchAuthentication(request)

        then:
        authentication
        "bar" == authentication.name
    }

    void "token validator order is preserved when multiple validators authenticate the same token"() {
        when:
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.setAttribute(LOW_PRECEDENCE_VALIDATOR_LATCH, new CountDownLatch(1))
        request.headers.add("X-API-KEY", "aaa")
        Authentication authentication = fetchAuthentication(request)

        then:
        authentication
        "high-precedence" == authentication.name
    }

    void "lower precedence validator is used when higher precedence validator returns empty"() {
        when:
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "bbb")
        Authentication authentication = fetchAuthentication(request)

        then:
        authentication
        "baz" == authentication.name
    }

    private Authentication fetchAuthentication(SimpleHttpRequest request) {
        Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()
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
            super.findToken(request)
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
    static class HighPrecedenceApiKeyTokenValidator implements TokenValidator<HttpRequest<?>> {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            if (token.equals("xxx")) {
                return Mono.just(Authentication.build("bar"))
            }
            if (token.equals("yyy")) {
                return Mono.just(Authentication.build("foo"))
            }
            if (token.equals("aaa")) {
                return Mono.fromCallable {
                    CountDownLatch latch = request?.getAttribute(LOW_PRECEDENCE_VALIDATOR_LATCH, CountDownLatch)
                        .orElseThrow { new IllegalStateException("Missing validator coordination latch") }
                    if (!latch.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting for the lower precedence validator")
                    }
                    Authentication.build("high-precedence")
                }.subscribeOn(Schedulers.boundedElastic())
            }
            Mono.empty()
        }

        @Override
        int getOrder() {
            return HIGHEST_PRECEDENCE
        }
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherSpec")
    @Singleton
    static class LowPrecedenceApiKeyTokenValidator implements TokenValidator<HttpRequest<?>> {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            if (token.equals("aaa")) {
                CountDownLatch latch = request?.getAttribute(LOW_PRECEDENCE_VALIDATOR_LATCH, CountDownLatch)
                    .orElseThrow { new IllegalStateException("Missing validator coordination latch") }
                return Mono.just(Authentication.build("low-precedence"))
                    .doOnNext { latch.countDown() }
            }
            if (token.equals("bbb")) {
                return Mono.just(Authentication.build("baz"))
            }
            Mono.empty()
        }

        @Override
        int getOrder() {
            return LOWEST_PRECEDENCE
        }
    }
}
