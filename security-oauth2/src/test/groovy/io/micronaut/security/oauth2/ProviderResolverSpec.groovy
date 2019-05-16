package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class ProviderResolverSpec extends Specification {

    void "test a provider resolver implementation exists"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true
        ])

        expect:
        ctx.containsBean(ProviderResolver)
    }
}
