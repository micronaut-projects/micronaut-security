package io.micronaut.docs.security.token.basicauth;

//tag::imports[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.ImperativeAuthenticationProvider;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

//end::imports[]
@Requires(property = "spec.name", value = "BlockingBasicAuthSpec")
//tag::clazz[]
@Named(ImperativeAuthenticationProviderUserPassword.NAME)
@Singleton
public class ImperativeAuthenticationProviderUserPassword<T> implements ImperativeAuthenticationProvider<T> {
    public static final String NAME = "foo";
    @Override
    public AuthenticationResponse authenticate(T httpRequest,
                                               AuthenticationRequest<?, ?> authenticationRequest) {
        return (
                authenticationRequest.getIdentity().equals("user") &&
                authenticationRequest.getSecret().equals("password")
        ) ? AuthenticationResponse.success("user") :
                AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
    }

    @Override
    public @NonNull String getName() {
        return ImperativeAuthenticationProviderUserPassword.NAME;
    }
}
//end::clazz[]
