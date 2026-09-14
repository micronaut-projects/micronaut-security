package io.micronaut.security.token

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.event.TokenValidatedEvent
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.token.reader.HttpHeaderTokenReader
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono
import groovy.transform.Canonical
import spock.lang.Specification

import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList

@Property(name = "spec.name", value = "TokenAuthenticationFetcherSpec")
@MicronautTest
class TokenAuthenticationFetcherSpec extends Specification {

    @Inject
    TokenAuthenticationFetcher tokenAuthenticationFetcher

    @Inject
    ValidatorInvocations validatorInvocations

    @Inject
    TokenValidatedEventListener tokenValidatedEventListener

    void setup() {
        validatorInvocations.clear()
        tokenValidatedEventListener.events.clear()
    }

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

    void "the first reader's token wins even when its validator is asynchronous and a later reader's token validates synchronously"() {
        given: 'X-API-KEY (highest precedence reader) is validated asynchronously, Authorization (lower precedence reader) synchronously'
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "async-first")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer sync-second")

        when:
        Authentication authentication = fetchAuthentication(request)

        then: 'the token read by the highest precedence reader wins'
        authentication
        "async-first-user" == authentication.name

        and: 'the token recorded on the request is the winning token'
        request.getAttribute(SecurityFilter.TOKEN, String).get() == "async-first"

        and: 'exactly one TokenValidatedEvent is published and it carries the winning token'
        tokenValidatedEventListener.events.size() == 1
        tokenValidatedEventListener.events[0].source == "async-first"

        and: 'the second token is never validated'
        validatorInvocations.tokens() == ["async-first"]
        !validatorInvocations.tokens().contains("sync-second")
    }

    void "token validator order is preserved when multiple validators authenticate the same token"() {
        given: 'the higher precedence validator succeeds asynchronously, the lower one synchronously'
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "aaa")

        when:
        Authentication authentication = fetchAuthentication(request)

        then: 'the higher precedence validator result wins'
        authentication
        "high-precedence" == authentication.name

        and: 'the lower precedence validator is never subscribed'
        validatorInvocations.invocations == [new Invocation("high", "aaa")]

        and: 'the token is recorded once'
        request.getAttribute(SecurityFilter.TOKEN, String).get() == "aaa"
        tokenValidatedEventListener.events.size() == 1
        tokenValidatedEventListener.events[0].source == "aaa"
    }

    void "lower precedence validator is used when higher precedence validator returns empty"() {
        when:
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "bbb")
        Authentication authentication = fetchAuthentication(request)

        then:
        authentication
        "baz" == authentication.name
        validatorInvocations.invocations == [new Invocation("high", "bbb"), new Invocation("low", "bbb")]
    }

    void "a validator error is treated as a failed validation and the next validator is tried"() {
        given: 'the higher precedence validator errors, the lower one authenticates'
        MemoryAppender appender = attachAppender()
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "error-then-ok")

        when:
        Authentication authentication = fetchAuthentication(request)

        then: 'the lower precedence validator authenticates'
        authentication
        "recovered" == authentication.name

        and: 'both validators were tried, in order'
        validatorInvocations.invocations == [new Invocation("high", "error-then-ok"), new Invocation("low", "error-then-ok")]

        and: 'the token is recorded and the event published once'
        request.getAttribute(SecurityFilter.TOKEN, String).get() == "error-then-ok"
        tokenValidatedEventListener.events.size() == 1
        tokenValidatedEventListener.events[0].source == "error-then-ok"

        and: 'the validator failure was logged at WARN without the token value'
        appender.events.size() == 1
        appender.events[0].level == Level.WARN
        appender.events[0].formattedMessage.contains(HighPrecedenceApiKeyTokenValidator.name)
        appender.events[0].formattedMessage.contains("jwks unavailable")
        !appender.events[0].formattedMessage.contains("error-then-ok")

        cleanup:
        detachAppender(appender)
    }

    void "a validator error on the first token does not prevent a later token from authenticating"() {
        given: 'both validators error for the X-API-KEY token, the Authorization token is valid'
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "all-error")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")

        when:
        Authentication authentication = fetchAuthentication(request)

        then:
        authentication
        "foo" == authentication.name
        validatorInvocations.invocations == [new Invocation("high", "all-error"), new Invocation("low", "all-error"), new Invocation("high", "yyy")]
        request.getAttribute(SecurityFilter.TOKEN, String).get() == "yyy"
        tokenValidatedEventListener.events*.source == ["yyy"]
    }

    void "when every validator errors the fetcher emits empty and logs a warning without the token value"() {
        given:
        MemoryAppender appender = attachAppender()
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "all-error")

        when:
        Authentication authentication = fetchAuthentication(request)

        then: 'no error is propagated and no authentication is produced'
        noExceptionThrown()
        authentication == null

        and: 'every validator was tried'
        validatorInvocations.invocations == [new Invocation("high", "all-error"), new Invocation("low", "all-error")]

        and: 'no token is recorded and no event is published'
        !request.getAttribute(SecurityFilter.TOKEN, String).isPresent()
        tokenValidatedEventListener.events.isEmpty()

        and: 'one WARN per failed validator, naming the validator and the exception but never the token'
        appender.events.size() == 2
        appender.events.every { it.level == Level.WARN }
        appender.events[0].formattedMessage.contains(HighPrecedenceApiKeyTokenValidator.name)
        appender.events[1].formattedMessage.contains(LowPrecedenceApiKeyTokenValidator.name)
        appender.events.every { it.formattedMessage.contains("jwks unavailable") }
        appender.events.every { !it.formattedMessage.contains("all-error") }

        cleanup:
        detachAppender(appender)
    }

    void "a validator that throws synchronously is treated as a failed validation"() {
        given:
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "throws-then-ok")

        when:
        Authentication authentication = fetchAuthentication(request)

        then:
        noExceptionThrown()
        authentication
        "recovered" == authentication.name
        validatorInvocations.invocations == [new Invocation("high", "throws-then-ok"), new Invocation("low", "throws-then-ok")]
    }

    private Authentication fetchAuthentication(SimpleHttpRequest request) {
        Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()
    }

    private static MemoryAppender attachAppender() {
        MemoryAppender appender = new MemoryAppender()
        Logger logger = (Logger) LoggerFactory.getLogger(TokenAuthenticationFetcher.class)
        logger.addAppender(appender)
        appender.start()
        appender
    }

    private static void detachAppender(MemoryAppender appender) {
        Logger logger = (Logger) LoggerFactory.getLogger(TokenAuthenticationFetcher.class)
        logger.detachAppender(appender)
        appender.stop()
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final List<ILoggingEvent> events = new CopyOnWriteArrayList<>()

        @Override
        protected void append(ILoggingEvent e) {
            events.add(e)
        }
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

        private final ValidatorInvocations invocations

        HighPrecedenceApiKeyTokenValidator(ValidatorInvocations invocations) {
            this.invocations = invocations
        }

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            invocations.record("high", token)
            if (token.equals("xxx")) {
                return Mono.just(Authentication.build("bar"))
            }
            if (token.equals("yyy")) {
                return Mono.just(Authentication.build("foo"))
            }
            if (token.equals("aaa")) {
                return Mono.delay(Duration.ofMillis(200)).map { Authentication.build("high-precedence") }
            }
            if (token.equals("async-first")) {
                return Mono.delay(Duration.ofMillis(200)).map { Authentication.build("async-first-user") }
            }
            if (token.equals("sync-second")) {
                return Mono.just(Authentication.build("sync-second-user"))
            }
            if (token.equals("error-then-ok") || token.equals("all-error")) {
                return Mono.error(new IllegalStateException("jwks unavailable"))
            }
            if (token.equals("throws-then-ok")) {
                throw new IllegalStateException("jwks unavailable")
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

        private final ValidatorInvocations invocations

        LowPrecedenceApiKeyTokenValidator(ValidatorInvocations invocations) {
            this.invocations = invocations
        }

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            invocations.record("low", token)
            if (token.equals("aaa")) {
                return Mono.just(Authentication.build("low-precedence"))
            }
            if (token.equals("bbb")) {
                return Mono.just(Authentication.build("baz"))
            }
            if (token.equals("error-then-ok") || token.equals("throws-then-ok")) {
                return Mono.just(Authentication.build("recovered"))
            }
            if (token.equals("all-error")) {
                return Mono.error(new IllegalStateException("jwks unavailable"))
            }
            Mono.empty()
        }

        @Override
        int getOrder() {
            return LOWEST_PRECEDENCE
        }
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherSpec")
    @Singleton
    static class ValidatorInvocations {
        final List<Invocation> invocations = new CopyOnWriteArrayList<>()

        void record(String validator, String token) {
            invocations.add(new Invocation(validator, token))
        }

        List<String> tokens() {
            invocations*.token
        }

        void clear() {
            invocations.clear()
        }
    }

    @Canonical
    static class Invocation {
        String validator
        String token
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherSpec")
    @Singleton
    static class TokenValidatedEventListener implements ApplicationEventListener<TokenValidatedEvent> {
        final List<TokenValidatedEvent> events = new CopyOnWriteArrayList<>()

        @Override
        void onApplicationEvent(TokenValidatedEvent event) {
            events.add(event)
        }
    }
}
