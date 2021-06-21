package io.micronaut.security.authentication

import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class BasicAuthAuthenticationFetcherSpec extends ApplicationContextSpecification {

    void "by default BasicAuthAuthenticationFetcher exists"() {
        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)
    }
}
