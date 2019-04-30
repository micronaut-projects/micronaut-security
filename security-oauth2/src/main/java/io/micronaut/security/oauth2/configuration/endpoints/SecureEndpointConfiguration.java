package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;

import java.util.Optional;

public interface SecureEndpointConfiguration extends EndpointConfiguration {

    Optional<AuthenticationMethod> getAuthMethod();
}
