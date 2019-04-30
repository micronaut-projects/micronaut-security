package io.micronaut.security.oauth2.configuration;

import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;

import java.util.Optional;

public interface OpenIdConfiguration {

    Optional<EndSessionConfiguration> getEndSession();
}
