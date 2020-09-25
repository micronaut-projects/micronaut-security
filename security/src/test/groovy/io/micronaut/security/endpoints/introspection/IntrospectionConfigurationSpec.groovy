package io.micronaut.security.endpoints.introspection

import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.endpoints.introspection.IntrospectionConfiguration

class IntrospectionConfigurationSpec extends ApplicationContextSpecification {

    void "by default there is a bean of type IntrospectionConfiguration"() {
        expect:
        applicationContext.containsBean(IntrospectionConfiguration)
    }

    void "introspection endpoint path defaults to /token_info"() {
        expect:
        '/token_info' == applicationContext.getBean(IntrospectionConfiguration).path
    }
}
