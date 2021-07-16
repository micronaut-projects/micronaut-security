package io.micronaut.docs.websockets;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;
import jakarta.inject.Singleton;
import java.util.ArrayList;

@Requires(property = "spec.name", value = "websockets")
@Singleton
public class MockAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flux.create(emitter -> {
            emitter.next(new UserDetails("john", new ArrayList<>()));
            emitter.complete();
        }, FluxSink.OverflowStrategy.ERROR);
    }
}
