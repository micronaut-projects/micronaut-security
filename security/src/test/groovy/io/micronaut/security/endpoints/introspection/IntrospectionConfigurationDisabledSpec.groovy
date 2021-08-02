package io.micronaut.security.endpoints.introspection

import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.endpoints.introspection.IntrospectionConfiguration
import io.micronaut.security.endpoints.introspection.IntrospectionController
import io.micronaut.security.endpoints.introspection.IntrospectionProcessor

class IntrospectionConfigurationDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.introspection.enabled': false
        ]
    }
    void "you can disable the bean IntrospectionConfiguration by setting micronaut.security.endpoints.introspection.enabled to false"() {
        expect:
        !applicationContext.containsBean(IntrospectionConfiguration)
        !applicationContext.containsBean(IntrospectionProcessor)
        !applicationContext.containsBean(IntrospectionController)
    }
}
