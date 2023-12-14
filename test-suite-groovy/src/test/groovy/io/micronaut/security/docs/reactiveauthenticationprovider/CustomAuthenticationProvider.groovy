package io.micronaut.security.docs.reactiveauthenticationprovider;

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestReactiveAuthenticationProvider;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

@Requires(property = "spec.name", value = "ReactiveAuthenticationProviderTest")
//tag::clazz[]
@Singleton
class CustomAuthenticationProvider<B> implements HttpRequestReactiveAuthenticationProvider<B> {
    @Override
    @SingleResult
    Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<B> httpRequest,
                                                   @NonNull AuthenticationRequest<String, String> authRequest) {
        AuthenticationResponse rsp = (authRequest.identity == "user" && authRequest.secret == "password")
                ? AuthenticationResponse.success("user")
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        return Mono.create(emitter -> {
            emitter.success(rsp)
        })
    }
}
//end::clazz[]
