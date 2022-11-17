package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.core.util.StringUtils
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEConfigurationSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE
        ]
    }

    void "PKCEConfiguration defaults to cookie when enabled"() {
        when:
        PKCEConfiguration pKCEConfiguration = applicationContext.getBean(PKCEConfiguration.class)

        then:
        noExceptionThrown()

        and:
        pKCEConfiguration.isEnabled()

        and: 'default persistence is cookie'
        pKCEConfiguration.getPersistence().isPresent()
        pKCEConfiguration.getPersistence().get() == 'cookie'
    }
}
