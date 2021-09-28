package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.core.annotation.ReflectiveAccess
import spock.lang.Specification

class OpenIdTokenResponseSpec extends Specification {
    void "OpenIdTokenResponse is annotated with ReflectiveAccess"() {
        expect:
        OpenIdTokenResponse.class.isAnnotationPresent(ReflectiveAccess)
    }
}
