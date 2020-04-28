package io.micronaut.security.token.validator;

import java.util.Optional;

/**
 * Responsible for validating a refresh token
 * is in a valid format. This logic is separate from determining
 * if the refresh token has been revoked or otherwise not
 * present in the persistence layer.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
public interface RefreshTokenValidator {

    /**
     * @param refreshToken The refresh token
     * @return True if the refresh token is valid
     */
    Optional<String> validate(String refreshToken);
}
