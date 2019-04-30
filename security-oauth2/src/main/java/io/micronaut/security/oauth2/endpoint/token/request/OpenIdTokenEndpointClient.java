package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;

public interface OpenIdTokenEndpointClient<T extends OpenIdTokenResponse> extends TokenEndpointClient<T> {
}
