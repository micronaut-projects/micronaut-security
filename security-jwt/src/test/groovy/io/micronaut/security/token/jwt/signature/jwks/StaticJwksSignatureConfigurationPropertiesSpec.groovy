package io.micronaut.security.token.jwt.signature.jwks

import io.micronaut.security.testutils.ApplicationContextSpecification

class StaticJwksSignatureConfigurationPropertiesSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.jwks-static.google.path': 'classpath:security/jwks.json'
        ] as Map<String, Object>
    }

    void "bean of type StaticJwksSignatureConfiguration exists when you provide configuration"() {
        expect:
        applicationContext.containsBean(StaticJwksSignatureConfiguration)
    }
}
