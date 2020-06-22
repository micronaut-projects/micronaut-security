package io.micronaut.security.authentication

import io.micronaut.security.ApplicationContextSpecification

class BasicAuthAuthenticationFetcherSpec extends ApplicationContextSpecification {

    void "by default BasicAuthAuthenticationFetcher exists"() {
        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)
    }
}
