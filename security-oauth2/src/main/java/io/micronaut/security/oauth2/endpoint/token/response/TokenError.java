package io.micronaut.security.oauth2.endpoint.token.response;

/**
 * {@see https://tools.ietf.org/html/rfc6749#section-5.2}
 */
public enum TokenError {

    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    INVALID_GRANT("invalid_grant"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
    INVALID_SCOPE("invalid_scope");

    private String errorCode;

    /**
     * @param errorCode The error code
     */
    TokenError(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     *
     * @return An errorCode code.
     */
    @Override
    public String toString() {
        return errorCode;
    }

}
