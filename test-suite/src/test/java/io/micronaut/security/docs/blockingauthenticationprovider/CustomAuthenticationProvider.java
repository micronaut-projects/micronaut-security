package io.micronaut.security.docs.blockingauthenticationprovider;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

@Requires(property = "spec.name", value = "AuthenticationProviderTest")
//tag::clazz[]
@Named(CustomAuthenticationProvider.NAME)
@Singleton
class CustomAuthenticationProvider implements AuthenticationProvider<HttpRequest<?>> {
    static final String NAME = "foo";

    @Override
    public AuthenticationResponse authenticate(HttpRequest<?> httpRequest,
                                               AuthenticationRequest<?, ?> authenticationRequest) {
        return (
                authenticationRequest.getIdentity().equals("user") &&
                authenticationRequest.getSecret().equals("password")
        ) ? AuthenticationResponse.success("user") :
                AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
    }

    @Override
    public @NonNull String getName() {
        return NAME;
    }
}
//end::clazz[]
