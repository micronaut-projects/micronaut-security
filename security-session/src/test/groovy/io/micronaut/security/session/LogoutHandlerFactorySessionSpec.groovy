package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification

class LogoutHandlerFactorySessionSpec extends ApplicationContextSpecification {
    void "by default no bean of type LogoutHandlerFactorySession exists"() {
        expect:
        !applicationContext.containsBean(LogoutHandlerFactorySession)
    }
}
