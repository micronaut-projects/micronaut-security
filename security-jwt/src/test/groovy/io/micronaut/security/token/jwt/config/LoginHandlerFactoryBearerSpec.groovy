package io.micronaut.security.token.jwt.config

import io.micronaut.testutils.ApplicationContextSpecification

class LoginHandlerFactoryBearerSpec extends ApplicationContextSpecification {

    void "by default no bean of type LoginHandlerFactoryBearer exists"() {
        expect:
        !applicationContext.containsBean(LoginHandlerFactoryBearer)
    }
}
