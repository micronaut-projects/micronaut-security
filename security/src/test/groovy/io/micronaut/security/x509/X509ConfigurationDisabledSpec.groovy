package io.micronaut.security.x509

import io.micronaut.security.testutils.ApplicationContextSpecification

class X509ConfigurationDisabledSpec extends ApplicationContextSpecification {

    void 'by default no io.micronaut.security.x509.X509Configuration bean exists if micronaut.security.x509.enabled is not set to true'() {
        expect:
        !applicationContext.containsBean(X509Configuration)
    }
}
