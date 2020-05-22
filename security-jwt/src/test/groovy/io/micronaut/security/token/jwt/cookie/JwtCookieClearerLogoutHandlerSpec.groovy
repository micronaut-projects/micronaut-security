package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.security.handlers.AuthenticationMode
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

}
