package io.micronaut.security.oauth2.endpoint.authorization.pkce

import spock.lang.Specification

class Sha256ConditionSpec extends Specification {

    void "Sha256 condition evaluates to true"() {
        expect:
        new Sha256Condition().matches(null)
    }
}
