package io.micronaut.security.authentication

import groovy.transform.AutoImplement
import spock.lang.Specification

class AuthenticationSpec extends Specification {

    @AutoImplement
    static class TestAuthentication implements Authentication {

        @Override
        Map<String, Object> getAttributes() {
            return Map.of("string", "string", "int", 0, "boolean", true)
        }
    }

    def "getAttribute returns the desired explicitly typed optional"() {
        expect:
        new TestAuthentication().getAttribute("string", String.class) == Optional.of("string")
        new TestAuthentication().getAttribute("int", Integer.class) == Optional.of(0)
        new TestAuthentication().getAttribute("boolean", Boolean.class) == Optional.of(true)
    }

    def "getAttribute returns empty optional when type is incorrect"() {
        expect:
        new TestAuthentication().getAttribute("string", Void.class) == Optional.empty()
        new TestAuthentication().getAttribute("int", Void.class) == Optional.empty()
        new TestAuthentication().getAttribute("boolean", Void.class) == Optional.empty()
    }
}
