package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;

import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;
//end::clazz[]

@Requires(property = "spec.name", value = "docsbasicauth")
//tag::clazz[]
@Singleton
public class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
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
