package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class ProviderResolverSpec extends Specification implements ConfigurationFixture {

    void "test a provider resolver implementation exists"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(oauth2Config)

        expect:
        ctx.containsBean(ProviderResolver)
    }
}
