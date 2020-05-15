package io.micronaut.security.token.jwt.generator

import io.micronaut.testutils.ApplicationContextSpecification

class RefreshTokenConfigurationToggeableSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.token.jwt.generator.refresh-token.enabled': 'false'
        ] as Map<String, Object>
    }

    void "by default no bean of type RefreshTokenConfiguration exists"() {
        expect:
        !applicationContext.containsBean(RefreshTokenConfiguration)
    }
}
