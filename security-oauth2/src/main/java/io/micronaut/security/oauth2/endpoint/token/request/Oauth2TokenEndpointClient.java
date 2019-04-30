package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;

public interface Oauth2TokenEndpointClient<T extends TokenResponse> extends TokenEndpointClient<T> {
}
