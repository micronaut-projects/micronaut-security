package io.micronaut.security.endpoints

import io.micronaut.security.testutils.ApplicationContextSpecification

class OauthControllerConfigurationPropertiesSpec extends ApplicationContextSpecification {

    void "OauthControllerConfiguration is enabled by default"() {
        when:
        OauthControllerConfiguration configuration = applicationContext.getBean(OauthControllerConfiguration)

        then:
        configuration.enabled
    }

    void "OauthControllerConfigurationProperties#setEnabled honours the supplied value"() {
        given:
        OauthControllerConfigurationProperties configuration = new OauthControllerConfigurationProperties()

        expect:
        configuration.enabled

        when:
        configuration.enabled = false

        then:
        !configuration.enabled

        when:
        configuration.enabled = true

        then:
        configuration.enabled
    }
}
