package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.*;
import org.reactivestreams.Publisher;

import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
//end::clazz[]

@Requires(property = "spec.name", value = "docsbasicauth")
//tag::clazz[]
@Singleton
public class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Mono.<AuthenticationResponse>create(emitter -> {
            if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
                emitter.success(new UserDetails("user", new ArrayList<>()));
            } else {
                emitter.error(new AuthenticationException(new AuthenticationFailed()));
            }
        });
    }
}
//end::clazz[]
