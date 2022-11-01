package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.serde.ObjectMapper
import spock.lang.PendingFeature
import spock.lang.Specification

class TokenErrorSpec extends Specification {

    @PendingFeature(reason = "https://github.com/micronaut-projects/micronaut-serialization/issues/297")
    void "TokenError should be deserializable from a string"() {
        setup:
        ObjectMapper objectMapper = ObjectMapper.getDefault()
        when:
        def deserializationResult = objectMapper.readValue('"unauthorized_client"', TokenError)
        then:
        deserializationResult == TokenError.UNAUTHORIZED_CLIENT
    }
}
