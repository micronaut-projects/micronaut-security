package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

class TokenErrorSpec extends Specification {

    void "TokenError should be deserializable from a string"() {
        setup:
        def objectMapper = new ObjectMapper()
        when:
        def deserializationResult = objectMapper.readValue('"unauthorized_client"', TokenError)
        then:
        deserializationResult == TokenError.UNAUTHORIZED_CLIENT
    }
}
