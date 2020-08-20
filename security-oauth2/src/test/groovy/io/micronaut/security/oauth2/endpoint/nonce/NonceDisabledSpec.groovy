package io.micronaut.security.oauth2.endpoint.nonce

import io.micronaut.security.oauth2.ApplicationContextSpecification
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence

class NonceDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.openid.nonce.enabled': false
        ]
    }

    void "micronaut.security.oauth2.openid.nonce.enabled: false disables nonce related beans"() {
        expect:
        !applicationContext.containsBean(NoncePersistence)
        !applicationContext.containsBean(NonceFactory)
        !applicationContext.containsBean(NonceConfiguration)
    }
}
