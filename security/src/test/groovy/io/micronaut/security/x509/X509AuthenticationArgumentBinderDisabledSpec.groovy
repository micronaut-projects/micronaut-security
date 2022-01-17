package io.micronaut.security.x509

import io.micronaut.security.testutils.ApplicationContextSpecification

class X509AuthenticationArgumentBinderDisabledSpec extends ApplicationContextSpecification {

    void 'by default no X509AuthenticationArgumentBinder bean exists if micronaut.security.x509.enabled is not set to true'() {
        expect:
        !applicationContext.containsBean(X509AuthenticationArgumentBinder)
    }
}
