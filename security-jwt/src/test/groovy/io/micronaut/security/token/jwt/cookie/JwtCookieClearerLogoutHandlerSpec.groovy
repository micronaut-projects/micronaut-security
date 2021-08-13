package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationMode
import io.micronaut.security.config.RedirectConfiguration
import io.micronaut.security.handlers.LogoutHandler
import spock.lang.Specification

class JwtCookieClearerLogoutHandlerSpec extends Specification {

    void "by default no bean of type JwtCookieClearerLogoutHandler exists"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([:])

        expect:
        !ctx.containsBean(JwtCookieClearerLogoutHandler)
        !ctx.containsBean(LogoutHandler)

        cleanup:
        ctx.close()
    }

    void "micronaut.security.authentication: cookie enables JwtCookieClearerLogoutHandler bean"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(['micronaut.security.authentication':'cookie'])

        expect:
        ctx.containsBean(JwtCookieClearerLogoutHandler)
        ctx.containsBean(LogoutHandler)

        cleanup:
        ctx.close()
    }

    void "micronaut.security.authentication: idtoken enables JwtCookieClearerLogoutHandler bean"(boolean expected, String mode) {
        given:
        ApplicationContext ctx = ApplicationContext.run(['micronaut.security.authentication': mode])

        expect:
        ctx.containsBean(JwtCookieClearerLogoutHandler) == expected
        ctx.containsBean(LogoutHandler) == expected

        cleanup:
        ctx.close()

        where:
        expected || mode
        true     || AuthenticationMode.COOKIE.toString()
        false    || AuthenticationMode.SESSION.toString()
        false    || AuthenticationMode.BEARER.toString()
        true     || AuthenticationMode.IDTOKEN.toString()
    }

    void "token and refresh token cookie are getting cleared on logout"() {
        given:
        RedirectConfiguration redirectConfiguration = Mock() {
            1 * getLogout() >> "logout"
        }
        AccessTokenCookieConfiguration accessTokenCookieConfiguration = Mock() {
            1 * getCookieDomain() >> Optional.of("domain")
            1 * getCookiePath() >> Optional.of("/")
            1 * getCookieName() >> "JWT"
        }
        RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = Mock() {
            1 * getCookieDomain() >> Optional.of("domain")
            1 * getCookiePath() >> Optional.of("/oauth/access_token")
            1 * getCookieName() >> "JWT_REFRESH"
        }
        HttpRequest<?> request = Mock()

        def handler = new JwtCookieClearerLogoutHandler(accessTokenCookieConfiguration, refreshTokenCookieConfiguration, redirectConfiguration);
        def response = handler.logout(request)
        def cookieHeaders = response.getHeaders().getAll("Set-Cookie")

        expect:
        cookieHeaders.size() == 2
        cookieHeaders.get(0).containsIgnoreCase("Domain=domain")
        cookieHeaders.get(0).containsIgnoreCase("JWT=")
        cookieHeaders.get(0).containsIgnoreCase("Path=/")
        cookieHeaders.get(0).containsIgnoreCase("Max-Age=0")
        cookieHeaders.get(1).containsIgnoreCase("Domain=domain")
        cookieHeaders.get(1).containsIgnoreCase("JWT_REFRESH=")
        cookieHeaders.get(1).containsIgnoreCase("Path=/oauth/access_token")
        cookieHeaders.get(1).containsIgnoreCase("Max-Age=0")
    }
}
