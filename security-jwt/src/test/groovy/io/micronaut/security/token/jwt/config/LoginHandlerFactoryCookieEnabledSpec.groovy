package io.micronaut.security.token.jwt.config


import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.handlers.LoginHandlerMode
import io.micronaut.security.token.jwt.cookie.JwtCookieLoginHandler
import io.micronaut.testutils.ApplicationContextSpecification

class LoginHandlerFactoryCookieEnabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.login-handler': LoginHandlerMode.COOKIE.toString()
        ]
    }

    void "if micronaut.security.login-handler=cookie then a login Handler of type JwtCookieLoginHandler is created"() {
        expect:
        applicationContext.containsBean(LoginHandlerFactoryCookie)
        applicationContext.containsBean(LoginHandler)
        applicationContext.getBean(LoginHandler) instanceof JwtCookieLoginHandler
    }
}
