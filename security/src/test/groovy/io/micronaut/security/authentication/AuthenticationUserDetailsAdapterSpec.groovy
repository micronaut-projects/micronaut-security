package io.micronaut.security.authentication

import io.micronaut.core.beans.BeanIntrospection
import spock.lang.Specification

class AuthenticationUserDetailsAdapterSpec extends Specification {
    void "AuthenticationUserDetailsAdapter is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(AuthenticationUserDetailsAdapter)

        then:
        noExceptionThrown()
    }
}
