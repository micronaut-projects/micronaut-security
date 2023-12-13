package io.micronaut.docs.security.principalparam

import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink

// Although this is a Groovy file this is written as close to Java as possible to embedded in the docs
@Requires(property = "spec.name", value = "principalparam")
//tag::clazz[]
@Singleton
class AuthenticationProviderUserPassword<T> implements ReactiveAuthenticationProvider<T> {

    @Override
    Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flux.create({emitter ->
            if (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password")) {
                emitter.next(AuthenticationResponse.success("user"))
                emitter.complete()
            } else {
                emitter.error(AuthenticationResponse.exception())
            }
        }, FluxSink.OverflowStrategy.ERROR)
    }
}
//end::clazz[]
