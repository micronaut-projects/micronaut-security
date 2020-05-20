package io.micronaut.security.handlers

import spock.lang.Specification
import spock.lang.Unroll

class LogoutHandlerModeSpec extends Specification {

    @Unroll("#type toString() is #expected")
    void "io.micronaut.security.handlers.LogoutHandlerType::toString() returns name as lowercase"(LogoutHandlerMode type, String expected) {
        expect:
        type.toString() == expected

        where:
        type                      || expected
        LogoutHandlerMode.COOKIE  || 'cookie'
        LogoutHandlerMode.SESSION || 'session'
    }
}
