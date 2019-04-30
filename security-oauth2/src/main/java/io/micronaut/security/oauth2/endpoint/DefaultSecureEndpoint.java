package io.micronaut.security.oauth2.endpoint;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Optional;


public class DefaultSecureEndpoint implements SecureEndpoint {

    private final String url;
    private final List<AuthenticationMethod> supportedAuthenticationMethods;

    public DefaultSecureEndpoint(@Nonnull String url,
                                 @Nullable List<AuthenticationMethod> supportedAuthenticationMethods) {
        this.url = url;
        this.supportedAuthenticationMethods = supportedAuthenticationMethods;
    }

    @Override
    @Nonnull
    public String getUrl() {
        return url;
    }

    @Override
    public Optional<List<AuthenticationMethod>> getSupportedAuthenticationMethods() {
        return Optional.ofNullable(supportedAuthenticationMethods);
    }
}
