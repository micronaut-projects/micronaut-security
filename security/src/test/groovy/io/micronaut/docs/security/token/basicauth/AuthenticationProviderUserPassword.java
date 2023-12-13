package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
//end::clazz[]

@Requires(property = "spec.name", value = "docsbasicauth")
//tag::clazz[]
@Singleton
public class AuthenticationProviderUserPassword<T> implements ReactiveAuthenticationProvider<T> {

    @Override
    public Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Mono.<AuthenticationResponse>create(emitter -> {
            if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
                emitter.success(AuthenticationResponse.success("user"));
            } else {
                emitter.error(AuthenticationResponse.exception());
            }
        });
    }
}
//end::clazz[]
