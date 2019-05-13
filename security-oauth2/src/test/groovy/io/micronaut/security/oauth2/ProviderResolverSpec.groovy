package io.micronaut.security.oauth2

class ProviderResolverSpec extends ApplicationContextSpecification {

    void "ProviderResolver bean exists"() {
        expect:
        applicationContext.containsBean(ProviderResolver)
    }
}
