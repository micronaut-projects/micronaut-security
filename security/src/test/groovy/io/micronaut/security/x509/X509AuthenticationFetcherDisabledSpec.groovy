package io.micronaut.security.x509

import io.micronaut.security.testutils.ApplicationContextSpecification

class X509AuthenticationFetcherDisabledSpec extends ApplicationContextSpecification {

    void 'no X509AuthenticationFetcher bean if x509.enabled is not set to true'() {
        expect:
        !applicationContext.containsBean(X509AuthenticationFetcher)
    }
}
