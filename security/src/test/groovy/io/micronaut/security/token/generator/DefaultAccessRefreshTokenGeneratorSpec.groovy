package io.micronaut.security.token.generator

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import io.micronaut.context.BeanContext
import io.micronaut.context.event.ApplicationEventPublisher
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.claims.ClaimsGenerator
import io.micronaut.security.token.render.AccessRefreshToken
import io.micronaut.security.token.render.TokenRenderer
import org.slf4j.LoggerFactory
import spock.lang.Specification

import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

class DefaultAccessRefreshTokenGeneratorSpec extends Specification {

    void "token generation failure with a null claim value returns empty and does not throw even with DEBUG enabled"() {
        given: 'DEBUG is enabled for the generator logger and its output is captured'
        Logger logger = (Logger) LoggerFactory.getLogger(DefaultAccessRefreshTokenGenerator)
        Level previousLevel = logger.level
        MemoryAppender appender = new MemoryAppender()
        logger.addAppender(appender)
        logger.setLevel(Level.DEBUG)
        appender.start()

        and: 'a token generator which fails to generate the access token'
        TokenGenerator tokenGenerator = Stub(TokenGenerator) {
            generateToken(_ as Map) >> Optional.empty()
            generateToken(_ as Authentication, _) >> Optional.empty()
        }
        ClaimsGenerator claimsGenerator = Stub(ClaimsGenerator) {
            generateClaimsSet(_ as Map, _) >> { Map<String, ?> oldClaims, Integer expiration -> new LinkedHashMap<String, Object>(oldClaims) }
        }
        AccessTokenConfiguration accessTokenConfiguration = Stub(AccessTokenConfiguration) {
            getExpiration() >> 3600
        }
        DefaultAccessRefreshTokenGenerator generator = new DefaultAccessRefreshTokenGenerator(
                accessTokenConfiguration,
                Stub(TokenRenderer),
                tokenGenerator,
                Stub(BeanContext),
                null,
                claimsGenerator,
                Stub(ApplicationEventPublisher),
                Stub(ApplicationEventPublisher))

        and: 'claims containing a null value and a value which must not be logged'
        Map<String, Object> claims = new HashMap<>()
        claims.put('sub', 'alice')
        claims.put('email', 'alice@example.com')
        claims.put('nickname', null)

        when:
        Optional<AccessRefreshToken> result = generator.generate('refresh-token', claims)

        then:
        noExceptionThrown()
        !result.isPresent()

        and: 'the debug line names the claims but writes none of their values'
        String message = appender.events.find { it.contains('failed to generate access token') }
        message
        message.contains('nickname')
        message.contains('email')
        !message.contains('alice')

        cleanup:
        logger.detachAppender(appender)
        logger.setLevel(previousLevel)
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final BlockingQueue<String> events = new LinkedBlockingQueue<>()

        @Override
        protected void append(ILoggingEvent e) {
            events.add(e.formattedMessage)
        }
    }
}
