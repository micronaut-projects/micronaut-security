package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;

import java.util.Map;

public class OpenIdCodeTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, OpenIdTokenResponse> {

    private final AuthorizationResponse authorizationResponse;
    private final CallbackUrlBuilder callbackUrlBuilder;

    public OpenIdCodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                         CallbackUrlBuilder callbackUrlBuilder,
                                         SecureEndpoint endpoint,
                                         OauthClientConfiguration clientConfiguration) {
        super(getMediaType(clientConfiguration), endpoint, clientConfiguration);
        this.authorizationResponse = authorizationResponse;
        this.callbackUrlBuilder = callbackUrlBuilder;
    }

    protected static MediaType getMediaType(OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getToken)
                .map(TokenEndpointConfiguration::getContentType)
                .orElse(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    @Override
    public Map<String, String> getGrant() {
        AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant();
        codeGrant.setCode(authorizationResponse.getCode());
        codeGrant.setRedirectUri(callbackUrlBuilder
                .build(authorizationResponse.getCallbackRequest(), clientConfiguration.getName()));
        return codeGrant.toMap();
    }

    @Override
    public Argument<OpenIdTokenResponse> getResponseType() {
        return Argument.of(OpenIdTokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(TokenErrorResponse.class);
    }
}
