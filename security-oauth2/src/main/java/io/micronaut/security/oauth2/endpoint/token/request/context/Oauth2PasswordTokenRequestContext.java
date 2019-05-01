package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MediaType;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenResponse;
import io.micronaut.security.oauth2.grants.PasswordGrant;

import java.util.Map;

public class Oauth2PasswordTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, DefaultTokenResponse> {

    private final AuthenticationRequest authenticationRequest;

    public Oauth2PasswordTokenRequestContext(AuthenticationRequest authenticationRequest,
                                             SecureEndpoint endpoint,
                                             OauthClientConfiguration clientConfiguration) {
        this(authenticationRequest, MediaType.APPLICATION_FORM_URLENCODED_TYPE, endpoint, clientConfiguration);
    }

    public Oauth2PasswordTokenRequestContext(AuthenticationRequest authenticationRequest,
                                             MediaType mediaType,
                                             SecureEndpoint endpoint,
                                             OauthClientConfiguration clientConfiguration) {
        super(mediaType, endpoint, clientConfiguration);
        this.authenticationRequest = authenticationRequest;
    }

    @Override
    public Map<String, String> getGrant() {
        PasswordGrant passwordGrant = new PasswordGrant();
        passwordGrant.setUsername(authenticationRequest.getIdentity().toString());
        passwordGrant.setPassword(authenticationRequest.getSecret().toString());
        passwordGrant.setScope(clientConfiguration.getScopes().stream()
                .reduce((a, b) -> a + StringUtils.SPACE + b)
                .orElse(StringUtils.EMPTY_STRING));
        return passwordGrant.toMap();
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
