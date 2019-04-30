package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represent the response of an authorization server to an invalid access token request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2>RFC 6749 Access Token Error Response</a>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class DefaultTokenErrorResponse implements TokenErrorResponse {

    private TokenError error;
    private String errorDescription;
    private String errorUri;

    /**
     * Default constructor
     */
    public DefaultTokenErrorResponse() {
    }

    @Nonnull
    public TokenError getError() {
        return error;
    }

    public void setError(TokenError error) {
        this.error = error;
    }

    @Nullable
    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    @Nullable
    public String getErrorUri() {
        return errorUri;
    }

    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }
}
