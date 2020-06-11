package io.micronaut.docs.websockets;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.token.config.TokenConfiguration;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import javax.inject.Singleton;

@Requires(property = "spec.name", value = "websockets")
@Singleton
public class MockAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flowable.create(emitter -> {
            emitter.onNext(AuthenticationResponse.build("john", new TokenConfiguration() {}));
            emitter.onComplete();
        }, BackpressureStrategy.ERROR);
    }
}
