package io.micronaut.security.token.jwt.cookie

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.session.LoginForm
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.cookie.Cookie
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.pages.HomePage
import io.micronaut.security.pages.LoginPage
import io.micronaut.security.annotation.Secured
import io.micronaut.security.endpoints.LoginController
import io.micronaut.security.endpoints.LogoutController
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import io.micronaut.security.testutils.ConfigurationFixture
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.utils.BaseUrlUtils
import io.micronaut.security.utils.HtmlUtils
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import org.testcontainers.DockerClientFactory
import spock.lang.IgnoreIf
import spock.lang.Shared

import java.security.Principal

class JwtCookieAuthenticationSpec extends GebSpec {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Shared
    ApplicationContext applicationContext = embeddedServer.applicationContext

    HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)

    BlockingHttpClient client = httpClient.toBlocking()

    @Override
    Browser getBrowser() {
        Browser browser = super.getBrowser()
        if (embeddedServer) {
            browser.baseUrl = BaseUrlUtils.getBaseUrl(embeddedServer)
        }
        browser
    }

    Map<String, Object> getConfiguration() {
        ConfigurationUtils.getConfiguration('JwtCookieAuthenticationSpec') + [
                'micronaut.http.client.followRedirects': false,
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': '/login/authFailed',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    def "verify jwt cookie authentication works without Geb"() {
        applicationContext.getBean(HomeController.class)
        applicationContext.getBean(LoginAuthController.class)
        applicationContext.getBean(AuthenticationProviderUserPassword.class)
        applicationContext.getBean(AuthenticationProviderUserPassword.class)
        applicationContext.getBean(LoginController.class)
        applicationContext.getBean(LogoutController.class)
        applicationContext.getBean(JwtCookieLoginHandler.class)
        applicationContext.getBean(JwtCookieClearerLogoutHandler.class)
        applicationContext.getBean(SignatureConfiguration.class)
        applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))

        when:
        applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        HttpRequest request = HttpRequest.GET('/')
        HttpResponse<String> rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'foo', password: 'foo'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        and: 'login fails, cookie is not set'
        !loginRsp.getHeaders().get('Set-Cookie')

        when:
        loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie
        cookie.contains('JWT=')
        cookie.contains('Path=/')

        when:
        String sessionId = cookie.substring('JWT='.size(), cookie.indexOf(';'))
        request = HttpRequest.GET('/').cookie(Cookie.of('JWT', sessionId))
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    @spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
    def "verify jwt cookie authentication works"() {
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
        loginPage.login('foo', 'foo')

        then:
        at LoginPage

        and:
        loginPage.hasErrors()

        when:
        loginPage.login('sherlock', 'password')

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == 'sherlock'

        when:
        homePage.logout()

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == null
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
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

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
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

