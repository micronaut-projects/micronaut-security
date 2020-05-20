package io.micronaut.security.token.jwt.config

import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.handlers.LoginHandlerMode
import io.micronaut.security.token.jwt.bearer.AccessRefreshTokenLoginHandler
import io.micronaut.testutils.ApplicationContextSpecification

class LoginHandlerFactoryBearerEnabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.login-handler': LoginHandlerMode.BEARER.toString()
        ]
    }

    void "if micronaut.security.login-handler=bearer then a login Handler of type AccessRefreshTokenLoginHandler is created"() {
        expect:
        applicationContext.containsBean(LoginHandlerFactoryBearer)
        applicationContext.containsBean(LoginHandler)
        applicationContext.getBean(LoginHandler) instanceof AccessRefreshTokenLoginHandler
    }
}
