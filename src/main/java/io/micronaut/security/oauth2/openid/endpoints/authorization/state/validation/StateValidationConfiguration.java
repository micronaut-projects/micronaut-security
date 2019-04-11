package io.micronaut.security.oauth2.openid.endpoints.authorization.state.validation;

import io.micronaut.core.util.Toggleable;

import javax.annotation.Nonnull;
import java.util.Optional;

public interface StateValidationConfiguration extends Toggleable {

    /**
     * @return The state persistence mechanism
     */
    @Nonnull
    Optional<String> getPersistence();
}
