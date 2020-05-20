package io.micronaut.security.token.jwt.config

import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.handlers.LogoutHandlerMode
import io.micronaut.security.token.jwt.cookie.JwtCookieClearerLogoutHandler
import io.micronaut.testutils.ApplicationContextSpecification

class LogoutHandlerFactoryCookieEnabledSpec  extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.logout-handler': LogoutHandlerMode.COOKIE.toString()
        ]
    }

    void "if micronaut.security.logout-handler=cookie then a login Handler of type JwtCookieLogoutHandler is created"() {
        expect:
        applicationContext.containsBean(LogoutHandlerFactoryCookie)
        applicationContext.containsBean(LogoutHandler)
        applicationContext.getBean(LogoutHandler) instanceof JwtCookieClearerLogoutHandler
    }
}
