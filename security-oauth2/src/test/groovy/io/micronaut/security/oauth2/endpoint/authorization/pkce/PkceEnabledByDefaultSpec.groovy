package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class PkceEnabledByDefaultSpec extends ApplicationContextSpecification {
    void "micronaut.security.oauth2.pkce.enabled: true enables pkce related beans"() {
        expect:
        applicationContext.containsBean(PkcePersistence)
        applicationContext.containsBean(PkceFactory)
        applicationContext.containsBean(PkceConfiguration)
    }
}
