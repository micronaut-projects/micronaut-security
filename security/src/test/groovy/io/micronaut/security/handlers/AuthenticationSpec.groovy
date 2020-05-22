package io.micronaut.security.handlers

import spock.lang.Specification
import spock.lang.Unroll

class AuthenticationSpec extends Specification {

    @Unroll("#type toString() is #expected")
    void "LoginHandlerType::toString() returns name as lowercase"(AuthenticationMode type, String expected) {
        expect:
        type.toString() == expected

        where:
        type                       || expected
        AuthenticationMode.BEARER  || 'bearer'
        AuthenticationMode.COOKIE  || 'cookie'
        AuthenticationMode.SESSION || 'session'
    }
}
