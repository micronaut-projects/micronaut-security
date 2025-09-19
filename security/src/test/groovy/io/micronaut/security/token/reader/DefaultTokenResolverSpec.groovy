package io.micronaut.security.token.reader

import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.order.Ordered
import io.micronaut.core.util.CollectionUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory
import spock.lang.Specification
import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

@Property(name = "spec.name", value = "DefaultTokenResolverSpec")
@MicronautTest
class DefaultTokenResolverSpec extends Specification {

    @Inject
    DefaultTokenResolver defaultTokenResolver

    void "Beans of type TokenReader are evaluated in order"() {
        given:
        MemoryAppender appender = new MemoryAppender()
        Logger logger = (Logger) LoggerFactory.getLogger(DefaultTokenResolver.class)
        logger.addAppender(appender)
        logger.setLevel(Level.TRACE)
        appender.start()

        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        String apiKey = "validxxx"
        request.headers.add("X-API-KEY", apiKey)

        when:
        Optional<String> tokenOptional = defaultTokenResolver.resolveToken(request)

        then:
        tokenOptional.isPresent()
        apiKey == tokenOptional.get()

        and: 'token is not logged'
        CollectionUtils.isNotEmpty(appender.events)
        1 == appender.events.size()
        appender.events.stream().noneMatch(e -> e.contains(apiKey))
        appender.events.stream().anyMatch(e -> e == "Token found in request POST /analytics/report")

        when:
        List<String> tokens = defaultTokenResolver.resolveTokens(request)

        then:
        [apiKey] == tokens

        when:
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)

        then:
        defaultTokenResolver.resolveToken(request).isEmpty()
        !defaultTokenResolver.resolveTokens(request)

        when:
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "validxxx")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer validyyy")

        then:
        defaultTokenResolver.resolveToken(request).isPresent()
        "validxxx" == defaultTokenResolver.resolveToken(request).get()
        ["validxxx", "validyyy"] == defaultTokenResolver.resolveTokens(request)

    }

    @Requires(property = "spec.name", value = "DefaultTokenResolverSpec")
    @Singleton
    static class ApiTokenReader extends HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null
        }

        @Override
        protected String getHeaderName() {
            return "X-API-KEY"
        }

        @Override
        int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final BlockingQueue<String> events = new LinkedBlockingQueue<>()

        @Override
        protected void append(ILoggingEvent e) {
            events.add(e.formattedMessage)
        }
    }
}
