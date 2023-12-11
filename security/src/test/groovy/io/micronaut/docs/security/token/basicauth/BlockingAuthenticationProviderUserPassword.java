package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.BlockingAuthenticationProvider;
import jakarta.inject.Singleton;
//end::clazz[]
@Requires(property = "spec.name", value = "BlockingBasicAuthSpec")
//tag::clazz[]
@Singleton
public class BlockingAuthenticationProviderUserPassword<T> implements BlockingAuthenticationProvider<T> {
    @Override
    public AuthenticationResponse authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
            return AuthenticationResponse.success("user");
        } else {
            throw AuthenticationResponse.exception();
        }
    }
}
//end::clazz[]
