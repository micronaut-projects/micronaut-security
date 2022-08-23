package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEFactorySpec extends ApplicationContextSpecification {

    void "by default bean of type PKCEFactory exists"() {
        expect:
        applicationContext.containsBean(PKCEFactory)
    }
}
