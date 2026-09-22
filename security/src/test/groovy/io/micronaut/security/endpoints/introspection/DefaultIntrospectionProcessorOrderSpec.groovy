package io.micronaut.security.endpoints.introspection

import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfigurationProperties
import io.micronaut.security.token.validator.TokenValidator
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger

class DefaultIntrospectionProcessorOrderSpec extends Specification {

    void "higher precedence TokenValidator wins even when it emits asynchronously after a lower precedence one could emit synchronously"() {
        given:
        HighPrecedenceTokenValidator high = new HighPrecedenceTokenValidator(true)
        LowPrecedenceTokenValidator low = new LowPrecedenceTokenValidator()
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([high, low], new TokenConfigurationProperties(), null)

        when:
        IntrospectionResponse response = Mono.from(processor.introspect(new IntrospectionRequest('token', null), HttpRequest.GET('/token_info'))).block()

        then:
        response.active
        response.username == 'high-precedence'

        and: 'the lower precedence validator was never consulted'
        low.invocations.get() == 0
    }

    void "lower precedence TokenValidator is consulted when the higher precedence one emits empty"() {
        given:
        HighPrecedenceTokenValidator high = new HighPrecedenceTokenValidator(false)
        LowPrecedenceTokenValidator low = new LowPrecedenceTokenValidator()
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([high, low], new TokenConfigurationProperties(), null)

        when:
        IntrospectionResponse response = Mono.from(processor.introspect(new IntrospectionRequest('token', null), HttpRequest.GET('/token_info'))).block()

        then:
        response.active
        response.username == 'low-precedence'
        low.invocations.get() == 1
    }

    static class HighPrecedenceTokenValidator implements TokenValidator<HttpRequest<?>> {

        private final boolean authenticates

        HighPrecedenceTokenValidator(boolean authenticates) {
            this.authenticates = authenticates
        }

        @Override
        Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            if (!authenticates) {
                return Mono.empty()
            }
            // Emit asynchronously after a delay so that a concurrently subscribed lower precedence validator would win the race.
            Mono.delay(Duration.ofMillis(200)).map { Authentication.build('high-precedence') }
        }

        @Override
        int getOrder() {
            Ordered.HIGHEST_PRECEDENCE
        }
    }

    static class LowPrecedenceTokenValidator implements TokenValidator<HttpRequest<?>> {

        final AtomicInteger invocations = new AtomicInteger()

        @Override
        Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            invocations.incrementAndGet()
            Mono.just(Authentication.build('low-precedence'))
        }

        @Override
        int getOrder() {
            Ordered.LOWEST_PRECEDENCE
        }
    }
}
