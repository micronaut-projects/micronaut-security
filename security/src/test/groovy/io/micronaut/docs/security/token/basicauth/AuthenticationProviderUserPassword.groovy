package io.micronaut.docs.security.token.basicauth;

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;
import java.util.ArrayList;

// Although this is a Groovy file this is written as close to Java as possible to embedded in the docs

@Requires(property = "spec.name", value = "docsbasicauth")
//tag::clazz[]
@Singleton
public class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
            return Flowable.just(new UserDetails("user", new ArrayList<>()));
        }
        return Flowable.just(new AuthenticationFailed());
    }
}
//end::clazz[]
