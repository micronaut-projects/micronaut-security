package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.serde.ObjectMapper
import spock.lang.Specification

class TokenErrorSpec extends Specification {

    void "TokenError should be deserializable from a string"() {
        setup:
        ObjectMapper objectMapper = ObjectMapper.getDefault()
        when:
        def deserializationResult = objectMapper.readValue('"unauthorized_client"', TokenError)
        then:
        deserializationResult == TokenError.UNAUTHORIZED_CLIENT
    }
}
