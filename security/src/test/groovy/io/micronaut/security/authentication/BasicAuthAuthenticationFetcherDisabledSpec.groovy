package io.micronaut.security.authentication

import io.micronaut.security.ApplicationContextSpecification

class BasicAuthAuthenticationFetcherDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ["micronaut.security.basic-auth.enabled": false]
    }

    void "If you set micronaut.security.basic-auth.enabled=false no bean of type BasicAuthAuthenticationFetcher exists"() {
        expect:
        !applicationContext.containsBean(BasicAuthAuthenticationFetcher)
    }
}
