package io.micronaut.security.token.jwt.cookie

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import io.micronaut.security.pages.HomePage
import io.micronaut.security.pages.LoginPage
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.ConfigurationFixture
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.utils.BaseUrlUtils
import io.micronaut.security.utils.HtmlUtils
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.IgnoreIf
import spock.lang.Shared

import java.security.Principal
import java.util.concurrent.ConcurrentHashMap

class JwtCookieRefreshSpec extends GebSpec {
    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Override
    Browser getBrowser() {
        Browser browser = super.getBrowser()
        if (embeddedServer) {
            browser.baseUrl = BaseUrlUtils.getBaseUrl(embeddedServer)
        }
        browser
    }

    Map<String, Object> getConfiguration() {
        ConfigurationUtils.getConfiguration('JwtCookieRefreshSpec') + [
            'micronaut.security.authentication': 'cookie',
            'micronaut.security.redirect.unauthorized.url': '/login/auth',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
            'micronaut.security.token.jwt.generator.refresh-token.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
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
        waitFor {
            at LoginPage
        }

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

    @Requires(property = 'spec.name', value = 'JwtCookieRefreshSpec')
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

    @Requires(property = "spec.name", value = "JwtCookieRefreshSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieRefreshSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller("/")
    static class HomeController {

        @Produces(MediaType.TEXT_HTML)
        @Get
        String index(@Nullable Principal principal) {
            return html(principal != null, principal != null ? principal.getName() : null)
        }

        @Produces(MediaType.TEXT_HTML)
        @Get("/secured")
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String securedPage() {
            HtmlUtils.securedPage()
        }

        private String html(boolean loggedIn, String username) {
            HtmlUtils.homePage(loggedIn, username)
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieRefreshSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller("/login")
    static class LoginAuthController {
        @Produces(MediaType.TEXT_HTML)
        @Get("/auth")
        String auth() {
            HtmlUtils.login(false)
        }

        @Produces(MediaType.TEXT_HTML)
        @Get("/authFailed")
        String authFailed() {
            HtmlUtils.login(true)
        }
    }
}
