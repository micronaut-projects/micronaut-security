package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class PkceDisabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.oauth2.pkce.enabled': false]
    }

    void "micronaut.security.oauth2.pkce.enabled: false disables pkce related beans"() {
        expect:
        !applicationContext.containsBean(PkcePersistence)
        !applicationContext.containsBean(PkceFactory)
        !applicationContext.containsBean(PkceConfiguration)
    }
}
