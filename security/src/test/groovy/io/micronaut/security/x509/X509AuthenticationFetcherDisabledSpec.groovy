package io.micronaut.security.x509

import io.micronaut.security.testutils.ApplicationContextSpecification

class X509AuthenticationFetcherDisabledSpec extends ApplicationContextSpecification {

    void 'by default no X509AuthenticationFetcher bean exists if micronaut.security.x509.enabled is not set to true'() {
        expect:
        !applicationContext.containsBean(X509AuthenticationFetcher)
    }
}
