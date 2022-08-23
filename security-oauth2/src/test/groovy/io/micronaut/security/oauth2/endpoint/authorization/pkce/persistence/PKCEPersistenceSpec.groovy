package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence

import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie.CookiePKCEPersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEPersistenceSpec extends ApplicationContextSpecification {

    void "bean of Type PKCEPersistenceSpec exists by default"() {
        expect:
        applicationContext.containsBean(PKCEPersistence)

        and:
        applicationContext.getBean(PKCEPersistence) instanceof CookiePKCEPersistence
    }
}
