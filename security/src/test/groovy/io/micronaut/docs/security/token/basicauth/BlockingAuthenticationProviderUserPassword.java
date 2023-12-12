package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.BlockingAuthenticationProvider;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
//end::clazz[]
@Requires(property = "spec.name", value = "BlockingBasicAuthSpec")
//tag::clazz[]
@Named(BlockingAuthenticationProviderUserPassword.NAME)
@Singleton
public class BlockingAuthenticationProviderUserPassword<T> implements BlockingAuthenticationProvider<T> {
    public static final String NAME = "foo";
    @Override
    public AuthenticationResponse authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
            return AuthenticationResponse.success("user");
        } else {
            throw AuthenticationResponse.exception();
        }
    }

    @Override
    public @NonNull String getName() {
        return BlockingAuthenticationProviderUserPassword.NAME;
    }
}
//end::clazz[]
