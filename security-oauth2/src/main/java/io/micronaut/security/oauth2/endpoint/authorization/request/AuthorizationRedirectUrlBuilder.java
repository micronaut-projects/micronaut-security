package io.micronaut.security.oauth2.endpoint.authorization.request;

public interface AuthorizationRedirectUrlBuilder {

    String buildUrl(AuthorizationRequest authorizationRequest,
                    String authorizationEndpoint);
}
