package io.micronaut.security.errors

import spock.lang.Specification
import spock.lang.Unroll

class IssuingAnAccessTokenErrorCodeSpec extends Specification {

    @Unroll("#errorCode toString() => #expected")
    void "IssuingAnAccessTokenErrorCode::toString() returns error code"(IssuingAnAccessTokenErrorCode errorCode, String expected) {
        expect:
        errorCode.toString() == expected

        and: 'getErrorCode is identical to toString()'
        errorCode.toString() == errorCode.getErrorCode()

        and: 'getErrorDescription is different than getErrorCode'
        errorCode.getErrorCodeDescription() != errorCode.getErrorCode()

        where:
        errorCode                                            || expected
        IssuingAnAccessTokenErrorCode.INVALID_CLIENT         || 'invalid_client'
        IssuingAnAccessTokenErrorCode.INVALID_GRANT          || 'invalid_grant'
        IssuingAnAccessTokenErrorCode.INVALID_REQUEST        || 'invalid_request'
        IssuingAnAccessTokenErrorCode.UNAUTHORIZED_CLIENT    || 'unauthorized_client'
        IssuingAnAccessTokenErrorCode.UNSUPPORTED_GRANT_TYPE || 'unsupported_grant_type'
    }
}
