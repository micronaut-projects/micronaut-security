package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;

import javax.annotation.Nonnull;
import java.util.Optional;

public class DefaultSecureEndpointConfiguration extends DefaultEndpointConfiguration implements SecureEndpointConfiguration {

    private AuthenticationMethod authMethod = AuthenticationMethod.CLIENT_SECRET_BASIC;

    @Override
    public Optional<AuthenticationMethod> getAuthMethod() {
        return Optional.ofNullable(authMethod);
    }

    public void setAuthMethod(@Nonnull AuthenticationMethod authMethod) {
        this.authMethod = authMethod;
    }
}
