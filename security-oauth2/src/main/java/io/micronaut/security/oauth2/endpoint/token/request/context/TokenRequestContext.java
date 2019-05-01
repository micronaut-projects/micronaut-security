package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;

public interface TokenRequestContext<G, R extends TokenResponse> {

    G getGrant();

    Argument<R> getResponseType();

    Argument<?> getErrorResponseType();

    MediaType getMediaType();

    SecureEndpoint getEndpoint();

    OauthClientConfiguration getClientConfiguration();
}
