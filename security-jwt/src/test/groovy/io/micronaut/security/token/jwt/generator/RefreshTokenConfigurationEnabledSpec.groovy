package io.micronaut.security.token.jwt.generator

import com.nimbusds.jose.JWSAlgorithm
import io.micronaut.testutils.ApplicationContextSpecification

class RefreshTokenConfigurationEnabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
        ] as Map<String, Object>
    }

    void "when you configure a secret a bean of type RefreshTokenConfiguration is found"() {
        expect:
        applicationContext.containsBean(RefreshTokenConfiguration)

        when:
        RefreshTokenConfiguration conf = applicationContext.getBean(RefreshTokenConfiguration)

        then:
        conf.secret == 'pleaseChangeThisSecretForANewOne'

        and: 'algorithm defaults to HS256'
        conf.jwsAlgorithm == JWSAlgorithm.HS256

        and: 'base 64 defaults to false'
        !conf.base64
    }
}
