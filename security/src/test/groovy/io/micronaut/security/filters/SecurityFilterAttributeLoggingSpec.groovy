package io.micronaut.security.filters

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.micronaut.context.annotation.Requires
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
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono

class SecurityFilterAttributeLoggingSpec extends EmbeddedServerSpecification {

    // Mirrors OauthAuthenticationMapper.ACCESS_TOKEN_KEY / REFRESH_TOKEN_KEY and OpenIdAuthenticationMapper.OPENID_TOKEN_KEY
    private static final String ACCESS_TOKEN = 'access-token-secret-value'
    private static final String REFRESH_TOKEN = 'refresh-token-secret-value'
    private static final String OPENID_TOKEN = 'openid-token-secret-value'
    private static final String CUSTOM_TOKEN = 'custom-token-secret-value'
    private static final String EMAIL = 'alice@example.com'

    private Logger logger
    private Level originalLevel
    private ListAppender<ILoggingEvent> appender

    @Override
    String getSpecName() {
        'SecurityFilterAttributeLoggingSpec'
    }

    void setup() {
        logger = (Logger) LoggerFactory.getLogger(SecurityFilter)
        originalLevel = logger.level
        appender = new ListAppender<>()
        appender.start()
        logger.addAppender(appender)
    }

    void cleanup() {
        logger.detachAppender(appender)
        appender.stop()
        logger.level = originalLevel
    }

    void "at DEBUG only the authentication attribute keys are logged, never the values"() {
        given:
        logger.level = Level.DEBUG

        when:
        String username = client.retrieve(HttpRequest.GET('/attribute-logging'))

        then:
        username == 'alice'

        and: 'the attribute keys are logged'
        List<String> messages = appender.list*.formattedMessage
        String attributesMessage = messages.find { it.startsWith('Authentication attributes:') }
        attributesMessage
        attributesMessage.contains('accessToken')
        attributesMessage.contains('refreshToken')
        attributesMessage.contains('openIdToken')
        attributesMessage.contains('email')

        and: 'no attribute value is logged'
        messages.every { !it.contains(ACCESS_TOKEN) }
        messages.every { !it.contains(REFRESH_TOKEN) }
        messages.every { !it.contains(OPENID_TOKEN) }
        messages.every { !it.contains(CUSTOM_TOKEN) }
        messages.every { !it.contains(EMAIL) }
    }

    void "at TRACE attribute values are logged but token values are redacted"() {
        given:
        logger.level = Level.TRACE

        when:
        String username = client.retrieve(HttpRequest.GET('/attribute-logging'))

        then:
        username == 'alice'

        and: 'non sensitive values are logged'
        List<String> messages = appender.list*.formattedMessage
        String attributesMessage = messages.find { it.startsWith('Authentication attributes:') }
        attributesMessage
        attributesMessage.contains("email=>${EMAIL}")

        and: 'token values are redacted'
        attributesMessage.contains('accessToken=><redacted>')
        attributesMessage.contains('refreshToken=><redacted>')
        attributesMessage.contains('openIdToken=><redacted>')
        attributesMessage.contains('X-Custom-Token=><redacted>')
        messages.every { !it.contains(ACCESS_TOKEN) }
        messages.every { !it.contains(REFRESH_TOKEN) }
        messages.every { !it.contains(OPENID_TOKEN) }
        messages.every { !it.contains(CUSTOM_TOKEN) }
    }

    @Requires(property = 'spec.name', value = 'SecurityFilterAttributeLoggingSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller('/attribute-logging')
    static class AttributeLoggingController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }

    @Requires(property = 'spec.name', value = 'SecurityFilterAttributeLoggingSpec')
    @Singleton
    static class TokenAttributesAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            Map<String, Object> attributes = new LinkedHashMap<>()
            attributes.put('accessToken', ACCESS_TOKEN)
            attributes.put('refreshToken', REFRESH_TOKEN)
            attributes.put('openIdToken', OPENID_TOKEN)
            attributes.put('X-Custom-Token', CUSTOM_TOKEN)
            attributes.put('email', EMAIL)
            Mono.just(Authentication.build('alice', attributes))
        }
    }
}
