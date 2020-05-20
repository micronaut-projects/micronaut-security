package io.micronaut.security.handlers

import spock.lang.Specification
import spock.lang.Unroll

class LoginHandlerModeSpec extends Specification {

    @Unroll("#type toString() is #expected")
    void "LoginHandlerType::toString() returns name as lowercase"(LoginHandlerMode type, String expected) {
        expect:
        type.toString() == expected

        where:
        type                     || expected
        LoginHandlerMode.BEARER  || 'bearer'
        LoginHandlerMode.COOKIE  || 'cookie'
        LoginHandlerMode.SESSION || 'session'
    }
}
