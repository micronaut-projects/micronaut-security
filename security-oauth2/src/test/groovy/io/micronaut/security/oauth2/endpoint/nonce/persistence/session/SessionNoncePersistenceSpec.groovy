package io.micronaut.security.oauth2.endpoint.nonce.persistence.session

import io.micronaut.security.oauth2.ApplicationContextSpecification
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence

class SessionNoncePersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.session.enabled': true,
                'micronaut.security.oauth2.openid.nonce.persistence': 'session'

        ]
    }

    void "NoncePersistence is an instance of SessionNoncePersistence"() {
        expect:
        applicationContext.containsBean(NoncePersistence)

        applicationContext.getBean(NoncePersistence) instanceof SessionNoncePersistence
    }
}
