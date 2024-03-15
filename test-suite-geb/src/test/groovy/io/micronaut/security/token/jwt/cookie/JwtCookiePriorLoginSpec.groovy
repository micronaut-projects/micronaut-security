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
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.pages.LoginPage
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.oauth2.keycloak.v16.Keycloak
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.utils.BaseUrlUtils
import io.micronaut.security.utils.HtmlUtils
import jakarta.inject.Singleton
import org.testcontainers.DockerClientFactory
import spock.lang.AutoCleanup
import spock.lang.IgnoreIf
import spock.lang.Shared

import java.security.Principal

@spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
class JwtCookiePriorLoginSpec extends GebSpec {
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
        ConfigurationUtils.getConfiguration('JwtCookiePriorLoginSpec') + [
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.prior-to-login': true,
                'micronaut.security.redirect.unauthorized.url': '/login/auth',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test prior login behavior"() {
        when:
        browser.via(SecuredPage)

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('sherlock', 'password')

        then:
        at SecuredPage
    }

    @Requires(property = "spec.name", value = "JwtCookiePriorLoginSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookiePriorLoginSpec")
    @Secured("isAnonymous()")
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

    @Requires(property = "spec.name", value = "JwtCookiePriorLoginSpec")
    @Secured("isAnonymous()")
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
