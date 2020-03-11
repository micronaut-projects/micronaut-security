package io.micronaut.security.token.jwt.generator;

import io.micronaut.core.util.Toggleable;

import java.util.Optional;

public interface RefreshTokenConfiguration extends TokenConfiguration, Toggleable {

    Optional<String> getSecret();
}
