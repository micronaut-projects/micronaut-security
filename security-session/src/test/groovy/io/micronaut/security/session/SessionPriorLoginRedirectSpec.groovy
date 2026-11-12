package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.LoadBalancer
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Unroll

class SessionPriorLoginRedirectSpec extends EmbeddedServerSpecification {

    private static final String COOKIE_NAME = 'ORIGINAL_URI'
    private static final String LOGIN_SUCCESS = '/home'

    @AutoCleanup
    @Shared
    BlockingHttpClient noRedirectClient = applicationContext.createBean(HttpClient,
            LoadBalancer.fixed(embeddedServer.getURL()),
            new DefaultHttpClientConfiguration(followRedirects: false),
            null).toBlocking()

    @Override
    String getSpecName() {
        'SessionPriorLoginRedirectSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'session',
                'micronaut.security.redirect.prior-to-login': true,
                'micronaut.security.redirect.login-success': LOGIN_SUCCESS,
                'micronaut.security.redirect.unauthorized.url': '/login/auth',
        ]
    }

    void "a relative path with a query string persisted prior to login is used as the post-login redirect"() {
        when: 'a browser hits a secured page without being authenticated'
        HttpResponse<?> unauthorized = noRedirectClient.exchange(HttpRequest.GET('/secured/page?foo=bar&baz=qux')
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML))

        then: 'it is redirected to the login page and the original path and query are stored in a cookie'
        unauthorized.status() == HttpStatus.SEE_OTHER
        unauthorized.header(HttpHeaders.LOCATION) == '/login/auth'
        Cookie originalUri = unauthorized.getCookie(COOKIE_NAME).orElse(null)
        originalUri
        originalUri.value == '/secured/page?foo=bar&baz=qux'

        when: 'the user logs in presenting the cookie'
        HttpResponse<?> login = noRedirectClient.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password'))
                .cookie(Cookie.of(COOKIE_NAME, originalUri.value)))

        then: 'the user is sent back to the original page and the cookie is cleared'
        login.status() == HttpStatus.SEE_OTHER
        login.header(HttpHeaders.LOCATION) == '/secured/page?foo=bar&baz=qux'
        login.getCookie(COOKIE_NAME).isPresent()
        login.getCookie(COOKIE_NAME).get().maxAge == 0
    }

    @Unroll
    void "a cookie holding #value does not turn the post-login redirect into an open redirect"(String value) {
        when: 'the user logs in presenting a tampered cookie'
        HttpResponse<?> login = noRedirectClient.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password'))
                .cookie(Cookie.of(COOKIE_NAME, value)))

        then: 'the user is redirected to the configured login success URL, not to the external host'
        login.status() == HttpStatus.SEE_OTHER
        login.header(HttpHeaders.LOCATION) == LOGIN_SUCCESS

        and: 'the tampered cookie is cleared'
        login.getCookie(COOKIE_NAME).isPresent()
        login.getCookie(COOKIE_NAME).get().maxAge == 0

        where:
        value << ['https://evil.example/x', '//evil.example/x']
    }

    void "without a cookie the post-login redirect is the configured login success URL"() {
        when:
        HttpResponse<?> login = noRedirectClient.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password')))

        then:
        login.status() == HttpStatus.SEE_OTHER
        login.header(HttpHeaders.LOCATION) == LOGIN_SUCCESS
        !login.getCookie(COOKIE_NAME).isPresent()
    }

    @Requires(property = 'spec.name', value = 'SessionPriorLoginRedirectSpec')
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = 'spec.name', value = 'SessionPriorLoginRedirectSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller('/secured')
    static class SecuredController {

        @Produces(MediaType.TEXT_HTML)
        @Get('/page')
        String page() {
            '<html><body>secured</body></html>'
        }
    }

    @Requires(property = 'spec.name', value = 'SessionPriorLoginRedirectSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller('/login')
    static class LoginAuthController {

        @Produces(MediaType.TEXT_HTML)
        @Get('/auth')
        String auth() {
            '<html><body>login</body></html>'
        }
    }
}
