package io.micronaut.security.oauth2.endpoint.nonce

import io.micronaut.security.oauth2.ApplicationContextSpecification

class NonceFactorySpec extends ApplicationContextSpecification {

    void "by default bean of type NonceFactory exists"() {
        expect:
        applicationContext.containsBean(NonceFactory)
    }
}
