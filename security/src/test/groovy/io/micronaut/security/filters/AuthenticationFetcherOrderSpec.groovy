package io.micronaut.security.filters

import io.micronaut.context.annotation.Requires
import io.micronaut.core.order.Ordered
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger

class AuthenticationFetcherOrderSpec extends EmbeddedServerSpecification {

    private static final String HIGH_PRECEDENCE_HEADER = 'X-High-Precedence-User'
    private static final String LOW_PRECEDENCE_HEADER = 'X-Low-Precedence-User'

    @Override
    String getSpecName() {
        'AuthenticationFetcherOrderSpec'
    }

    void setup() {
        getBean(LowPrecedenceAuthenticationFetcher).invocations.set(0)
    }

    void "higher precedence AuthenticationFetcher wins even when it emits asynchronously after a lower precedence one could emit synchronously"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/fetcher-order')
                .header(HIGH_PRECEDENCE_HEADER, 'alice')
                .header(LOW_PRECEDENCE_HEADER, 'bob')

        when:
        String username = client.retrieve(request)

        then:
        username == 'alice'

        and: 'the lower precedence fetcher was never consulted'
        getBean(LowPrecedenceAuthenticationFetcher).invocations.get() == 0
    }

    void "lower precedence AuthenticationFetcher is consulted when the higher precedence one emits empty"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/fetcher-order')
                .header(LOW_PRECEDENCE_HEADER, 'bob')

        when:
        String username = client.retrieve(request)

        then:
        username == 'bob'
        getBean(LowPrecedenceAuthenticationFetcher).invocations.get() == 1
    }

    @Requires(property = 'spec.name', value = 'AuthenticationFetcherOrderSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller('/fetcher-order')
    static class FetcherOrderController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }

    @Requires(property = 'spec.name', value = 'AuthenticationFetcherOrderSpec')
    @Singleton
    static class HighPrecedenceAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            String username = request.headers.get(HIGH_PRECEDENCE_HEADER)
            if (StringUtils.isEmpty(username)) {
                return Mono.empty()
            }
            // Emit asynchronously after a delay so that a concurrently subscribed lower precedence fetcher would win the race.
            Mono.delay(Duration.ofMillis(200)).map { Authentication.build(username) }
        }

        @Override
        int getOrder() {
            Ordered.HIGHEST_PRECEDENCE
        }
    }

    @Requires(property = 'spec.name', value = 'AuthenticationFetcherOrderSpec')
    @Singleton
    static class LowPrecedenceAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

        final AtomicInteger invocations = new AtomicInteger()

        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            invocations.incrementAndGet()
            String username = request.headers.get(LOW_PRECEDENCE_HEADER)
            if (StringUtils.isEmpty(username)) {
                return Mono.empty()
            }
            Mono.just(Authentication.build(username))
        }

        @Override
        int getOrder() {
            Ordered.LOWEST_PRECEDENCE
        }
    }
}
