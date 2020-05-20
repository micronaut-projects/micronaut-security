package io.micronaut.security.token.jwt.config

import io.micronaut.testutils.ApplicationContextSpecification

class LogoutHandlerFactoryCookieSpec extends ApplicationContextSpecification {
    void "by default no bean of type LogoutHandlerFactoryCookie exists"() {
        expect:
        !applicationContext.containsBean(LogoutHandlerFactoryCookie)
    }
}
