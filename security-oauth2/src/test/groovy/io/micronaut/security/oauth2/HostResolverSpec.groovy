package io.micronaut.security.oauth2

import io.micronaut.security.oauth2.url.DefaultHostResolver
import io.micronaut.security.oauth2.url.HostResolver

class HostResolverSpec extends ApplicationContextSpecification {

    void "HostResolver bean exists"() {
        expect:
        applicationContext.containsBean(HostResolver)

        when:
        HostResolver resolver = applicationContext.getBean(HostResolver)

        then:
        resolver instanceof DefaultHostResolver

        and:
        ((DefaultHostResolver) resolver).getHostHeaderName() == 'Host'
        ((DefaultHostResolver) resolver).getSchemeHeaderName() == 'X-Forwarded-Proto'
    }
}
