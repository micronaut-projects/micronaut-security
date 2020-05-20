package io.micronaut.security.token.jwt.config

import io.micronaut.testutils.ApplicationContextSpecification

class LoginHandlerFactoryCookieSpec extends ApplicationContextSpecification {
    void "by default no bean of type LoginHandlerFactoryCookie exists"() {
        expect:
        !applicationContext.containsBean(LoginHandlerFactoryCookie)
    }
}
