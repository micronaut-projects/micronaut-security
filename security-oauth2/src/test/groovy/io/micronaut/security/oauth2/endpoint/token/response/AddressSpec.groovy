package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.security.testutils.ApplicationContextSpecification

class AddressSpec extends ApplicationContextSpecification {

    void "IntrospectionResponse is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(Address.class)

        then:
        noExceptionThrown()
    }
}
