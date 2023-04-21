package io.micronaut.security.token.jwt.signature.jwks

import io.micronaut.security.testutils.ApplicationContextSpecification

class StaticJwksSignatureConfigurationSpec extends ApplicationContextSpecification {

    void "by default no bean of type StaticJwksSignatureConfiguration exists"() {
        expect:
        !applicationContext.containsBean(StaticJwksSignatureConfiguration)
    }
}
