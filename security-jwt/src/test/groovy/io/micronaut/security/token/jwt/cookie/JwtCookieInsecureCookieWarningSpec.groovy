package io.micronaut.security.token.jwt.cookie

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import org.reactivestreams.Publisher
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.cookie.CookieLoginHandler
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory

class JwtCookieInsecureCookieWarningSpec extends EmbeddedServerSpecification {

    ListAppender<ILoggingEvent> appender
    Logger logger

    @Override
    String getSpecName() {
        'JwtCookieInsecureCookieWarningSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration +
                [
                        'micronaut.http.client.followRedirects': false,
                        'micronaut.security.authentication': 'cookie',
                        'micronaut.security.redirect.login-failure': '/login/authFailed',
                        'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                        'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                ]
    }

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

    void "a WARN recommending cookie-secure is logged only once across two logins over plain HTTP"() {
        when: 'first login over plain HTTP'
        HttpResponse loginRsp = client.exchange(loginRequest(), String)
        List<String> cookies = loginRsp.getHeaders().getAll('Set-Cookie')

        then: 'cookies are issued without Secure'
        cookies.size() == 2
        cookies.every { !it.contains('Secure') }

        and: 'exactly one WARN was logged'
        warnings().size() == 1
        warnings()[0].formattedMessage.contains('micronaut.security.token.cookie.cookie-secure=true')

        when: 'second login over plain HTTP'
        loginRsp = client.exchange(loginRequest(), String)

        then:
        loginRsp.getHeaders().getAll('Set-Cookie').size() == 2

        and: 'the WARN is not logged again'
        warnings().size() == 1
    }

    private static HttpRequest loginRequest() {
        HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
    }

    private List<ILoggingEvent> warnings() {
        appender.list.findAll { it.level == Level.WARN && it.loggerName == CookieLoginHandler.name }
    }

    @Requires(property = "spec.name", value = "JwtCookieInsecureCookieWarningSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider  {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( "sherlock")])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieInsecureCookieWarningSpec")
    @Singleton
    static class TestRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, Authentication> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getAuthentication())
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }
}
