package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;

import javax.annotation.Nonnull;
import java.util.Optional;

/**
 * Default implementation of {@link SecureEndpointConfiguration}.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
public class DefaultSecureEndpointConfiguration extends DefaultEndpointConfiguration implements SecureEndpointConfiguration {

    private AuthenticationMethod authMethod = AuthenticationMethod.CLIENT_SECRET_BASIC;

    @Override
    public Optional<AuthenticationMethod> getAuthMethod() {
        return Optional.ofNullable(authMethod);
    }

    /**
     *
     * @param authMethod Authentication Method
     */
    public void setAuthMethod(@Nonnull AuthenticationMethod authMethod) {
        this.authMethod = authMethod;
    }
}
