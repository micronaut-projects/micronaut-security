
package io.micronaut.docs.jwtclaimsoverride;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.token.config.TokenConfiguration;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Requires(property = "spec.name", value = "jwtclaimsoverride")
//tag::clazz[]
@Singleton
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final TokenConfiguration tokenConfiguration;

    public CustomAuthenticationProvider(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flowable.create(emitter -> {
            emitter.onNext(AuthenticationResponse.build("sherlock", Collections.singletonMap("email", "sherlock@micronaut.example"), tokenConfiguration));
            emitter.onComplete();
        }, BackpressureStrategy.ERROR);
    }
}
//end::clazz[]
