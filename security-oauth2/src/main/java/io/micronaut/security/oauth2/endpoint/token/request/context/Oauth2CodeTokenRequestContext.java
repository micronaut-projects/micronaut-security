package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;

import java.util.Map;

public class Oauth2CodeTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, DefaultTokenResponse> {

    private final AuthorizationResponse authorizationResponse;

    public Oauth2CodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                         SecureEndpoint endpoint,
                                         OauthClientConfiguration clientConfiguration) {
        this(authorizationResponse, MediaType.APPLICATION_FORM_URLENCODED_TYPE, endpoint, clientConfiguration);
    }

    public Oauth2CodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                         MediaType mediaType,
                                         SecureEndpoint endpoint,
                                         OauthClientConfiguration clientConfiguration) {
        super(mediaType, endpoint, clientConfiguration);
        this.authorizationResponse = authorizationResponse;
    }

    @Override
    public Map<String, String> getGrant() {
        AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant();
        codeGrant.setCode(authorizationResponse.getCode());
        return codeGrant.toMap();
    }

    @Override
    public Argument<DefaultTokenResponse> getResponseType() {
        return Argument.of(DefaultTokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(DefaultTokenErrorResponse.class);
    }
}
