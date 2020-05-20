package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.handlers.LogoutHandlerMode

class LogoutHandlerFactorySessionEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.logout-handler': LogoutHandlerMode.SESSION.toString()
        ]
    }

    void "if micronaut.security.logout-handler=session then a login Handler of type SessionLogoutHandler is created"() {
        expect:
        applicationContext.containsBean(LogoutHandlerFactorySession)
        applicationContext.containsBean(LogoutHandler)
        applicationContext.getBean(LogoutHandler) instanceof SessionLogoutHandler
    }
}

