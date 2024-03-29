package io.micronaut.security.oauth2.endpoint.nonce.persistence

import io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie.CookieNoncePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class NoncePersistenceSpec extends ApplicationContextSpecification {

    void "bean of Type NoncePersistence exists by default"() {
        expect:
        applicationContext.containsBean(NoncePersistence)

        and:
        applicationContext.getBean(NoncePersistence) instanceof CookieNoncePersistence
    }
}