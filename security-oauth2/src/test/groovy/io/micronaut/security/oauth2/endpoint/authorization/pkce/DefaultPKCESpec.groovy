package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.core.annotation.ReflectiveAccess
import spock.lang.Specification

class DefaultPKCESpec extends Specification {

    void "DefaultPKCE is annotated with ReflectiveAccess"() {
        expect:
        DefaultPKCE.class.isAnnotationPresent(ReflectiveAccess)
    }
}
