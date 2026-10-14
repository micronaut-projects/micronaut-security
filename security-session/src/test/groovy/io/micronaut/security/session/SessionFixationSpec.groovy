package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.LoadBalancer
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.annotation.Secured
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import jakarta.inject.Singleton

class SessionFixationSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'session',
        ]
    }

    @Override
    String getSpecName() {
        'SessionFixationSpec'
    }

    void "login issues a new session and invalidates the pre-existing one"() {
        given:
        BlockingHttpClient client = noRedirectClient()
        SessionStore<Session> sessionStore = applicationContext.getBean(SessionStore)

        when: 'an anonymous request obtains a session (e.g. one planted by an attacker)'
        HttpResponse response = client.exchange(HttpRequest.GET("/visit"), String)
        String preLoginCookieId = getCookieId(response)
        String preLoginSessionId = getSessionId(preLoginCookieId)

        then:
        preLoginSessionId
        sessionStore.findSession(preLoginSessionId).get().isPresent()

        when: 'the user logs in with that session'
        response = client.exchange(loginRequest().cookie(Cookie.of("SESSION", preLoginCookieId)))
        String loginCookieId = getCookieId(response)
        String loginSessionId = getSessionId(loginCookieId)

        then: 'a new session identifier is issued'
        response.status() == HttpStatus.SEE_OTHER
        loginSessionId
        loginSessionId != preLoginSessionId

        and: 'the new session is authenticated'
        sessionStore.findSession(loginSessionId).get().get().get(SecurityFilter.AUTHENTICATION).isPresent()

        and: 'attributes of the previous session are migrated to the new session'
        sessionStore.findSession(loginSessionId).get().get().get("visited", String).get() == "true"

        and: 'the pre-existing session is deleted'
        !sessionStore.findSession(preLoginSessionId).get().isPresent()

        when: 'the pre-existing session identifier is used to access a secured endpoint'
        client.exchange(HttpRequest.GET("/secured").cookie(Cookie.of("SESSION", preLoginCookieId)), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when: 'the new session identifier is used to access a secured endpoint'
        response = client.exchange(HttpRequest.GET("/secured").cookie(Cookie.of("SESSION", loginCookieId)), String)

        then:
        response.status() == HttpStatus.OK
        response.body() == "sherlock"
    }

    void "logout deletes the session and expires the session cookie"() {
        given:
        BlockingHttpClient client = noRedirectClient()
        SessionStore<Session> sessionStore = applicationContext.getBean(SessionStore)

        when:
        HttpResponse response = client.exchange(loginRequest())
        String cookieId = getCookieId(response)
        String sessionId = getSessionId(cookieId)

        then:
        sessionStore.findSession(sessionId).get().get().get(SecurityFilter.AUTHENTICATION).isPresent()

        when:
        response = client.exchange(HttpRequest.POST("/logout", "")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .cookie(Cookie.of("SESSION", cookieId)))
        String setCookie = getSessionSetCookie(response)

        then: 'the session cookie is expired'
        response.status() == HttpStatus.SEE_OTHER
        setCookie
        setCookie.startsWith("SESSION=;")
        setCookie.contains("Max-Age=0")

        and: 'the session is deleted from the session store'
        !sessionStore.findSession(sessionId).get().isPresent()

        when: 'the old session identifier is used after logout'
        client.exchange(HttpRequest.GET("/secured").cookie(Cookie.of("SESSION", cookieId)), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when: 'the user logs in again with the old session identifier'
        response = client.exchange(loginRequest().cookie(Cookie.of("SESSION", cookieId)))
        String afterLoginSessionId = getSessionId(getCookieId(response))

        then: 'a different session is issued'
        afterLoginSessionId
        afterLoginSessionId != sessionId
        !sessionStore.findSession(sessionId).get().isPresent()
        sessionStore.findSession(afterLoginSessionId).get().get().get(SecurityFilter.AUTHENTICATION).isPresent()
    }

    private BlockingHttpClient noRedirectClient() {
        def config = new DefaultHttpClientConfiguration(followRedirects: false)
        applicationContext.createBean(HttpClient, LoadBalancer.fixed(embeddedServer.getURL()), config, null).toBlocking()
    }

    private static HttpRequest<?> loginRequest() {
        HttpRequest.POST("/login", "username=sherlock&password=password")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
    }

    private static String getSessionId(String cookieId) {
        new String(Base64.getDecoder().decode(cookieId))
    }

    private static String getSessionSetCookie(HttpResponse response) {
        response.getHeaders().getAll("set-cookie").find { it.startsWith("SESSION=") }
    }

    private static String getCookieId(HttpResponse response) {
        String setCookie = getSessionSetCookie(response)
        setCookie ? setCookie.split(";")[0].substring("SESSION=".length()) : null
    }

    @Requires(property = "spec.name", value = "SessionFixationSpec")
    @Controller
    static class VisitController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/visit")
        String visit(Session session) {
            session.put("visited", "true")
            "ok"
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secured")
        String secured(io.micronaut.security.authentication.Authentication authentication) {
            authentication.name
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = "SessionFixationSpec")
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider  {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }
}
