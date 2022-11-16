package io.micronaut.security.authentication

import io.micronaut.core.beans.BeanIntrospection
import spock.lang.Specification

class ServerAuthenticationSpec extends Specification {
    void "ServerAuthentication is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(ServerAuthentication)
        then:
        noExceptionThrown()
    }
}
