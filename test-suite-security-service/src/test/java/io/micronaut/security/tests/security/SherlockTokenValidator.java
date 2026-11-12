package io.micronaut.security.tests.security;

import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

@Singleton
public class SherlockTokenValidator implements TokenValidator {
    @Override
    public Publisher<Authentication> validateToken(String token, Object request) {
        return Publishers.just(Authentication.build("sherlock"));
    }
}
