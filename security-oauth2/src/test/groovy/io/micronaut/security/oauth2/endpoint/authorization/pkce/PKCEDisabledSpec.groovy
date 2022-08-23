package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PKCEPersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': false
        ]
    }

    void "micronaut.security.oauth2.pkce.enabled: false disables pkce related beans"() {
        expect:
        !applicationContext.containsBean(PKCEPersistence)
        !applicationContext.containsBean(PKCEFactory)
        !applicationContext.containsBean(DefaultPKCEConfiguration)
    }
}
