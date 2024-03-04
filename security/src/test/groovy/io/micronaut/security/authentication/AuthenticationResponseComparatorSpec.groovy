package io.micronaut.security.authentication

import spock.lang.Specification

class AuthenticationResponseComparatorSpec extends Specification {
    void "authenticated AuthenticationResponse have priority"() {
        given:
        AuthenticationResponse authenticationFailed = AuthenticationResponse.failure()
        AuthenticationResponse authenticationResponse = AuthenticationResponse.success("foo")
        List<AuthenticationResponse> l = [authenticationFailed, authenticationResponse]

        when:
        l.sort(new AuthenticationResponseComparator())

        then:
        l.get(0) == authenticationResponse
        l.get(1) == authenticationFailed
    }
}
