package io.micronaut.security.oauth2.endpoint.authorization.state

import io.micronaut.core.annotation.ReflectiveAccess
import spock.lang.Specification

class DefaultStateSpec extends Specification {

    void "DefaultState is annotated with ReflectiveAccess"() {
        expect:
        DefaultState.class.isAnnotationPresent(ReflectiveAccess)
    }
}
