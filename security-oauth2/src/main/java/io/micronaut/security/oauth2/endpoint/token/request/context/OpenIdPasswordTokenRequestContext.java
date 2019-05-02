package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MediaType;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.grants.PasswordGrant;

import java.util.Map;

public class OpenIdPasswordTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, OpenIdTokenResponse> {

    private final AuthenticationRequest authenticationRequest;

    public OpenIdPasswordTokenRequestContext(AuthenticationRequest authenticationRequest,
                                             SecureEndpoint endpoint,
                                             OauthClientConfiguration clientConfiguration) {
        super(getMediaType(clientConfiguration), endpoint, clientConfiguration);
        this.authenticationRequest = authenticationRequest;
    }

    @Override
    public Map<String, String> getGrant() {
        PasswordGrant passwordGrant = new PasswordGrant(authenticationRequest, clientConfiguration);
        return passwordGrant.toMap();
    }

    protected static MediaType getMediaType(OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getToken)
                .map(TokenEndpointConfiguration::getContentType)
                .orElse(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
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
