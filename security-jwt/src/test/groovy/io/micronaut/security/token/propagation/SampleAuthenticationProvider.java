package io.micronaut.security.token.propagation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Arrays;

@Requires(property = "spec.name", value = "tokenpropagation.gateway")
@Singleton
public class SampleAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flowable.create(emitter -> {
            if (authenticationRequest.getIdentity() == null) {
                emitter.onNext(new AuthenticationFailed());
                emitter.onComplete();
            } else if (authenticationRequest.getSecret() == null) {
                emitter.onNext(new AuthenticationFailed());
                emitter.onComplete();
            } else if (Arrays.asList("sherlock", "watson").contains(authenticationRequest.getIdentity().toString()) &&
                    authenticationRequest.getSecret().equals("elementary")) {
                emitter.onNext(new UserDetails(authenticationRequest.getIdentity().toString(), new ArrayList<>()));
                emitter.onComplete();
            } else {
                emitter.onNext(new AuthenticationFailed());
                emitter.onComplete();
            }
        },BackpressureStrategy.ERROR);


    }
}
