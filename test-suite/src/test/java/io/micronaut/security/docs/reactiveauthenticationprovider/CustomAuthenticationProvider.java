package io.micronaut.security.docs.reactiveauthenticationprovider;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

@Requires(property = "spec.name", value = "ReactiveAuthenticationProviderTest")
//tag::clazz[]
@Singleton
class CustomAuthenticationProvider implements ReactiveAuthenticationProvider<HttpRequest<?>> {
    @Override
    @SingleResult
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest,
                                                          AuthenticationRequest<?, ?> authRequest) {
        AuthenticationResponse rsp = authRequest.getIdentity().equals("user") && authRequest.getSecret().equals("password")
                ? AuthenticationResponse.success("user")
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        return Mono.create(emitter -> {
            emitter.success(rsp);
        });
    }
}
//end::clazz[]
