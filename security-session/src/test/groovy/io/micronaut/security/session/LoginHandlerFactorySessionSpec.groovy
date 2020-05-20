package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification

class LoginHandlerFactorySessionSpec extends ApplicationContextSpecification {
    void "by default no bean of type LoginHandlerFactorySession exists"() {
        expect:
        !applicationContext.containsBean(LoginHandlerFactorySession)
    }
}
