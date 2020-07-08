package io.micronaut.security.errors

import spock.lang.Specification
import spock.lang.Unroll

class ObtainingAuthorizationErrorCodeSpec extends Specification {
    @Unroll("#errorCode toString() => #expected")
    void "ObtainingAuthorizationErrorCode::toString() returns error code"(ObtainingAuthorizationErrorCode errorCode, String expected) {
        expect:
        errorCode.toString() == expected

        and: 'getErrorCode is identical to toString()'
        errorCode.toString() == errorCode.getErrorCode()

        and: 'getErrorDescription is different than getErrorCode'
        errorCode.getErrorCodeDescription() != errorCode.getErrorCode()

        where:
        errorCode                                                 || expected
        ObtainingAuthorizationErrorCode.INVALID_REQUEST           || 'invalid_request'
        ObtainingAuthorizationErrorCode.UNAUTHORIZED_CLIENT       || 'unauthorized_client'
        ObtainingAuthorizationErrorCode.ACCESS_DENIED             || 'access_denied'
        ObtainingAuthorizationErrorCode.INVALID_SCOPE             || 'invalid_scope'
        ObtainingAuthorizationErrorCode.SERVER_ERROR              || 'server_error'
        ObtainingAuthorizationErrorCode.TEMPORARILY_UNAVAILABLE   || 'temporarily_unavailable'
        ObtainingAuthorizationErrorCode.UNSUPPORTED_RESPONSE_TYPE || 'unsupported_response_type'
    }
}
