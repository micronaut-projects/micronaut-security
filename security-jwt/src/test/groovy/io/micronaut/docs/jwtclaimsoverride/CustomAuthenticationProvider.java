
package io.micronaut.docs.jwtclaimsoverride;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;

import jakarta.inject.Singleton;
import java.util.Collections;

@Requires(property = "spec.name", value = "jwtclaimsoverride")
//tag::clazz[]
@Singleton
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flux.create(emitter -> {
            emitter.next(AuthenticationResponse.success("sherlock", Collections.singletonMap("email", "sherlock@micronaut.example")));
            emitter.complete();
        }, FluxSink.OverflowStrategy.ERROR);
    }
}
//end::clazz[]
