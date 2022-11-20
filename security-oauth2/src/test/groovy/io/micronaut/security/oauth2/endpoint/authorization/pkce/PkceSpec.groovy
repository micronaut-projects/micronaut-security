package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.core.beans.BeanIntrospection
import spock.lang.Specification

class PkceSpec extends Specification {

    void "Pkce is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(Pkce)

        then:
        noExceptionThrown()
    }
}
