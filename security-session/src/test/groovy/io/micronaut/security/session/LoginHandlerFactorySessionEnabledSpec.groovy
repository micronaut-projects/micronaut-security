package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.handlers.LoginHandlerMode

class LoginHandlerFactorySessionEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.login-handler': LoginHandlerMode.SESSION.toString()
        ]
    }

    void "if micronaut.security.login-handler=session then a login Handler of type SessionLoginHandler is created"() {
        expect:
        applicationContext.containsBean(LoginHandlerFactorySession)
        applicationContext.containsBean(LoginHandler)
        applicationContext.getBean(LoginHandler) instanceof SessionLoginHandler
    }
}

