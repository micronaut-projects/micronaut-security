package io.micronaut.security.token.jwt.generator

import io.micronaut.security.testutils.ApplicationContextSpecification

class RefreshTokenConfigurationSpec extends ApplicationContextSpecification {

    void "by default no bean of type RefreshTokenConfiguration exists"() {
        expect:
        !applicationContext.containsBean(RefreshTokenConfiguration)
    }
}
