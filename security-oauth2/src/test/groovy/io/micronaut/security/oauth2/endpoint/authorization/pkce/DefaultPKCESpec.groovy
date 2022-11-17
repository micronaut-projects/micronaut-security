package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.core.annotation.ReflectiveAccess
import io.micronaut.core.beans.BeanIntrospection
import spock.lang.Specification

class DefaultPKCESpec extends Specification {

    void "DefaultPKCE is annotated with ReflectiveAccess"() {
        expect:
        DefaultPKCE.class.isAnnotationPresent(ReflectiveAccess)
    }
    
    void "DefaultPKCE is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(DefaultPKCE)

        then:
        noExceptionThrown()
    }
}
