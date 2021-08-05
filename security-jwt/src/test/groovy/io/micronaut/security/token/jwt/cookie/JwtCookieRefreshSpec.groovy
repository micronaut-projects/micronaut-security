package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpMethod
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.jwt.endpoints.OauthController
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.web.router.RouteMatch
import io.micronaut.web.router.Router
import org.reactivestreams.Publisher

import jakarta.inject.Singleton
import reactor.core.publisher.Mono

import java.util.concurrent.ConcurrentHashMap

class JwtCookieRefreshSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'JwtCookieAuthenticationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.authentication': 'cookie',
            'micronaut.security.redirect.unauthorized.url': '/login/auth',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
            'micronaut.security.token.jwt.generator.refresh-token.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    void "test the oauthcontroller is enabled"() {
        when:
        applicationContext.getBean(OauthController)

        then:
        noExceptionThrown()

        when:
        Optional<RouteMatch> match = applicationContext.getBean(Router).route(HttpMethod.GET, '/oauth/access_token')

        then:
        match.isPresent()
    }

    void "test refreshing the token"() {
        when:
        to HomePage

        then:
        at HomePage

        when:
        HomePage homePage = browser.page HomePage

        then:
        homePage.username() == null

        when:
        homePage.login()

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('sherlock', 'password')

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == 'sherlock'

        when:
        go '/oauth/access_token'

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == 'sherlock-refreshed'
    }

    @Requires(property = 'spec.name', value = 'JwtCookieAuthenticationSpec')
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        private final ConcurrentHashMap<String, Authentication> tokens = new ConcurrentHashMap<>()

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.computeIfAbsent(event.getRefreshToken(), (provider)  -> event.getAuthentication())
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            return Mono.just(tokens.computeIfPresent(refreshToken,
                    (s, auth) -> Authentication.build(auth.getName() + "-refreshed", auth.getAttributes())))
        }
    }
}
