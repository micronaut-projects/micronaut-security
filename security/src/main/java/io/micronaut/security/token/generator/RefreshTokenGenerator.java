package io.micronaut.security.token.generator;

import io.micronaut.security.authentication.UserDetails;

import java.util.Optional;

public interface RefreshTokenGenerator {

    String createKey(UserDetails userDetails);

    Optional<String> generate(UserDetails userDetails, String token);

    Optional<String> validate(String refreshToken);
}
