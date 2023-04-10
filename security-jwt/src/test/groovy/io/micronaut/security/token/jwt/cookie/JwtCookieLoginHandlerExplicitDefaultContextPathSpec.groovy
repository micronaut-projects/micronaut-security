package io.micronaut.security.token.jwt.cookie

import io.micronaut.http.HttpRequest
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.EmbeddedServerSpecification

class JwtCookieLoginHandlerExplicitDefaultContextPathSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': '/',
                'micronaut.security.authentication': 'cookie'
        ]
    }

    void "uses explicit default context path"() {
        given:
        JwtCookieLoginHandler loginHandler = applicationContext.getBean(JwtCookieLoginHandler)

        expect:
        '/' == loginHandler.loginFailure
        '/' == loginHandler.loginSuccess
        '/' == loginHandler.refresh

        when:
        def request = Mock(HttpRequest)
        Authentication authentication = Authentication.build("sherlock")
        List<Cookie> cookieList = loginHandler.getCookies(authentication, "xxx", request)

        then:
        cookieList

        when:
        Optional<Cookie> optionalCookie = cookieList.stream().filter(c -> c.name == JwtCookieConfigurationProperties.DEFAULT_COOKIENAME).findAny()

        then:
        optionalCookie.isPresent()
        "/" == optionalCookie.get().path


        when:
        Optional<Cookie> optionalRefreshCookie = cookieList.stream().filter(c -> c.name == RefreshTokenCookieConfigurationProperties.DEFAULT_COOKIENAME).findAny()

        then:
        optionalRefreshCookie.isPresent()
        "/oauth/access_token" == optionalRefreshCookie.get().path
    }
}
