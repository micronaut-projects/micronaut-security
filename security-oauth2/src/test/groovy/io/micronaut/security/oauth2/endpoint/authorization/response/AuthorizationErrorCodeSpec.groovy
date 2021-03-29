package io.micronaut.security.oauth2.endpoint.authorization.response

import spock.lang.Specification
import spock.lang.Unroll

class AuthorizationErrorCodeSpec extends Specification {
    @Unroll("#errorCode toString() => #expected")
    void "AuthorizationErrorCode::toString() returns error code"(AuthorizationErrorCode errorCode, String expected) {
        expect:
        errorCode.toString() == expected

        and: 'getErrorCode is identical to toString()'
        errorCode.toString() == errorCode.getErrorCode()

        and: 'getErrorDescription is different than getErrorCode'
        errorCode.getErrorCodeDescription() != errorCode.getErrorCode()

        and:
        errorCode == AuthorizationErrorCode.valueOf(expected.toUpperCase(Locale.ENGLISH))

        where:
        errorCode                                         || expected
        AuthorizationErrorCode.INVALID_REQUEST            || 'invalid_request'
        AuthorizationErrorCode.UNAUTHORIZED_CLIENT        || 'unauthorized_client'
        AuthorizationErrorCode.ACCESS_DENIED              || 'access_denied'
        AuthorizationErrorCode.INVALID_SCOPE              || 'invalid_scope'
        AuthorizationErrorCode.SERVER_ERROR               || 'server_error'
        AuthorizationErrorCode.TEMPORARILY_UNAVAILABLE    || 'temporarily_unavailable'
        AuthorizationErrorCode.UNSUPPORTED_RESPONSE_TYPE  || 'unsupported_response_type'
        AuthorizationErrorCode.ACCOUNT_SELECTION_REQUIRED || 'account_selection_required'
        AuthorizationErrorCode.CONSENT_REQUIRED           || 'consent_required'
        AuthorizationErrorCode.INTERACTION_REQUIRED       || 'interaction_required'
        AuthorizationErrorCode.INVALID_REQUEST_OBJECT     || 'invalid_request_object'
        AuthorizationErrorCode.INVALID_REQUEST_URI        || 'invalid_request_uri'
        AuthorizationErrorCode.LOGIN_REQUIRED             || 'login_required'
        AuthorizationErrorCode.REGISTRATION_NOT_SUPPORTED || 'registration_not_supported'
        AuthorizationErrorCode.REQUEST_NOT_SUPPORTED      || 'request_not_supported'
        AuthorizationErrorCode.REQUEST_URI_NOT_SUPPORTED  || 'request_uri_not_supported'
        AuthorizationErrorCode.USER_CANCELLED_AUTHORIZE   || 'user_cancelled_authorize'
        AuthorizationErrorCode.UNAUTHORIZED_SCOPE_ERROR   || 'unauthorized_scope_error'
    }
}
