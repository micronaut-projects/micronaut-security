package io.micronaut.security.token.cookie

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.config.RedirectConfiguration
import io.micronaut.security.config.RedirectService
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator
import io.micronaut.security.token.generator.AccessTokenConfiguration
import io.micronaut.security.token.render.AccessRefreshToken
import org.slf4j.LoggerFactory
import spock.lang.Specification

class TokenCookieLoginHandlerInsecureCookieWarningSpec extends Specification {

    ListAppender<ILoggingEvent> appender
    Logger logger

    def setup() {
        logger = (Logger) LoggerFactory.getLogger(CookieLoginHandler)
        appender = new ListAppender<>()
        appender.start()
        logger.addAppender(appender)
    }

    def cleanup() {
        logger.detachAppender(appender)
        appender.stop()
    }

    void "a WARN is logged once, not per request, when cookies are issued without Secure over an insecure request"() {
        given:
        TokenCookieLoginHandler handler = loginHandler(null)
        HttpRequest<?> request = Stub() {
            isSecure() >> false
        }
        Authentication authentication = Authentication.build('sherlock')

        when: 'first login'
        MutableHttpResponse<?> response = handler.loginSuccess(authentication, request)
        List<String> cookies = response.getHeaders().getAll('Set-Cookie')

        then: 'cookies are issued without Secure but with SameSite=Lax'
        cookies.size() == 2
        cookies.every { !it.contains('Secure') }
        cookies.every { it.contains('SameSite=Lax') }

        and: 'exactly one warning'
        warnings().size() == 1
        warnings()[0].formattedMessage.contains('micronaut.security.token.cookie.cookie-secure=true')

        when: 'second login'
        handler.loginSuccess(authentication, request)

        then: 'still exactly one warning'
        warnings().size() == 1

        when: 'refresh'
        handler.loginRefresh(authentication, 'refresh', request)

        then: 'still exactly one warning'
        warnings().size() == 1
    }

    void "no WARN is logged when the request is secure"() {
        given:
        TokenCookieLoginHandler handler = loginHandler(null)
        HttpRequest<?> request = Stub() {
            isSecure() >> true
        }

        when:
        MutableHttpResponse<?> response = handler.loginSuccess(Authentication.build('sherlock'), request)
        List<String> cookies = response.getHeaders().getAll('Set-Cookie')

        then:
        cookies.size() == 2
        cookies.every { it.contains('Secure') }
        warnings().isEmpty()
    }

    void "no WARN is logged when cookie-secure is explicitly true even over an insecure request"() {
        given:
        TokenCookieLoginHandler handler = loginHandler(true)
        HttpRequest<?> request = Stub() {
            isSecure() >> false
        }

        when:
        MutableHttpResponse<?> response = handler.loginSuccess(Authentication.build('sherlock'), request)
        List<String> cookies = response.getHeaders().getAll('Set-Cookie')

        then:
        cookies.size() == 2
        cookies.every { it.contains('Secure') }
        warnings().isEmpty()
    }

    private List<ILoggingEvent> warnings() {
        appender.list.findAll { it.level == Level.WARN }
    }

    private TokenCookieLoginHandler loginHandler(Boolean cookieSecure) {
        RedirectConfiguration redirectConfiguration = Stub() {
            isEnabled() >> false
        }
        RedirectService redirectService = Stub()
        TokenCookieConfigurationProperties accessTokenCookieConfiguration = new TokenCookieConfigurationProperties()
        accessTokenCookieConfiguration.setCookieSecure(cookieSecure)
        RefreshTokenCookieConfigurationProperties refreshTokenCookieConfiguration = new RefreshTokenCookieConfigurationProperties(null)
        refreshTokenCookieConfiguration.setCookieSecure(cookieSecure)
        AccessTokenConfiguration accessTokenConfiguration = Stub() {
            getExpiration() >> 3600
        }
        AccessRefreshTokenGenerator accessRefreshTokenGenerator = Stub() {
            generate(_ as Authentication) >> Optional.of(new AccessRefreshToken('access', 'refresh', 'Bearer', 3600))
            generate(_ as String, _ as Authentication) >> Optional.of(new AccessRefreshToken('access', 'refresh', 'Bearer', 3600))
        }
        new TokenCookieLoginHandler(redirectService,
                redirectConfiguration,
                accessTokenCookieConfiguration,
                refreshTokenCookieConfiguration,
                accessTokenConfiguration,
                accessRefreshTokenGenerator,
                null,
                [])
    }
}
