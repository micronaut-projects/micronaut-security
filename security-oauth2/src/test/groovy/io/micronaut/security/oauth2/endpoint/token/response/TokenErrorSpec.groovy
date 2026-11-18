package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.serde.ObjectMapper
import spock.lang.Shared
import spock.lang.Specification

class TokenErrorSpec extends Specification {

    @Shared
    ObjectMapper objectMapper = ObjectMapper.getDefault()

    void "TokenError #expected is deserializable from #json"(String json, TokenError expected) {
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
        expect:
        '"temporarily_unavailable"' == objectMapper.writeValueAsString(TokenError.TEMPORARILY_UNAVAILABLE)
        '"unknown"' == objectMapper.writeValueAsString(TokenError.UNKNOWN)
    }

    void "TokenError.of(#code) resolves to #expected"(String code, TokenError expected) {
        expect:
        TokenError.of(code) == expected

        where:
        code               | expected
        "invalid_token"    | TokenError.INVALID_TOKEN
        "Invalid_Token"    | TokenError.INVALID_TOKEN
        "INVALID_TOKEN"    | TokenError.INVALID_TOKEN
        "some_vendor_code" | TokenError.UNKNOWN
        " invalid_token"   | TokenError.UNKNOWN
        ""                 | TokenError.UNKNOWN
        null               | TokenError.UNKNOWN
    }

    void "every TokenError resolves from its own error code"(TokenError tokenError) {
        expect:
        TokenError.of(tokenError.errorCode) == tokenError
        tokenError.toString() == tokenError.errorCode
        tokenError.errorCode == tokenError.errorCode.toLowerCase(Locale.ROOT)

        where:
        tokenError << TokenError.values()
    }
}
