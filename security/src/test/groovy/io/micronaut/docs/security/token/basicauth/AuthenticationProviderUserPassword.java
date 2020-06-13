package io.micronaut.docs.security.token.basicauth;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.*;
import io.micronaut.security.token.config.TokenConfiguration;
import io.reactivex.Maybe;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;
//end::clazz[]

@Requires(property = "spec.name", value = "docsbasicauth")
//tag::clazz[]
@Singleton
public class AuthenticationProviderUserPassword implements AuthenticationProvider {

    private final TokenConfiguration tokenConfiguration;

    public AuthenticationProviderUserPassword(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Maybe.<AuthenticationResponse>create(emitter -> {
            if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
                emitter.onSuccess(AuthenticationResponse.build("user", tokenConfiguration));
            } else {
                emitter.onError(new AuthenticationException(new AuthenticationFailed()));
            }
        }).toFlowable();
    }
}
//end::clazz[]
