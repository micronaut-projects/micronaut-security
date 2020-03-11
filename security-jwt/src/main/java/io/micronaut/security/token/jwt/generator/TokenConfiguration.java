package io.micronaut.security.token.jwt.generator;

import java.util.Optional;

public interface TokenConfiguration {

    Optional<Integer> getExpiration();
}
