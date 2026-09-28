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

    void "TokenError #expected is deserializable from #json"(String json, TokenError expected) {
        setup:
        ObjectMapper objectMapper = ObjectMapper.getDefault()

        expect:
        expected == objectMapper.readValue(json, TokenError)

        where:
        json                          | expected
        '"invalid_request"'           | TokenError.INVALID_REQUEST
        '"invalid_client"'            | TokenError.INVALID_CLIENT
        '"invalid_grant"'             | TokenError.INVALID_GRANT
        '"unauthorized_client"'       | TokenError.UNAUTHORIZED_CLIENT
        '"unsupported_grant_type"'    | TokenError.UNSUPPORTED_GRANT_TYPE
        '"invalid_scope"'             | TokenError.INVALID_SCOPE
        '"access_denied"'             | TokenError.ACCESS_DENIED
        '"unsupported_response_type"' | TokenError.UNSUPPORTED_RESPONSE_TYPE
        '"server_error"'              | TokenError.SERVER_ERROR
        '"temporarily_unavailable"'   | TokenError.TEMPORARILY_UNAVAILABLE
        '"invalid_token"'             | TokenError.INVALID_TOKEN
        '"insufficient_scope"'        | TokenError.INSUFFICIENT_SCOPE
        '"unsupported_token_type"'    | TokenError.UNSUPPORTED_TOKEN_TYPE
        '"authorization_pending"'     | TokenError.AUTHORIZATION_PENDING
        '"slow_down"'                 | TokenError.SLOW_DOWN
        '"expired_token"'             | TokenError.EXPIRED_TOKEN
        '"unknown"'                   | TokenError.UNKNOWN
        '"some_vendor_code"'          | TokenError.UNKNOWN
        '"INVALID_GRANT"'             | TokenError.INVALID_GRANT
    }

    void "TokenError serializes to its error code"() {
        setup:
        ObjectMapper objectMapper = ObjectMapper.getDefault()

        expect:
        '"temporarily_unavailable"' == objectMapper.writeValueAsString(TokenError.TEMPORARILY_UNAVAILABLE)
        '"unknown"' == objectMapper.writeValueAsString(TokenError.UNKNOWN)
    }

    void "TokenError.of resolves known codes and falls back to UNKNOWN"() {
        expect:
        TokenError.of("invalid_token") == TokenError.INVALID_TOKEN
        TokenError.of("Invalid_Token") == TokenError.INVALID_TOKEN
        TokenError.of("some_vendor_code") == TokenError.UNKNOWN
        TokenError.of("") == TokenError.UNKNOWN
        TokenError.of(null) == TokenError.UNKNOWN
        TokenError.INVALID_TOKEN.errorCode == "invalid_token"
        TokenError.INVALID_TOKEN.toString() == "invalid_token"
    }
}
