package io.micronaut.security.handlers

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Flux
import org.reactivestreams.Publisher
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "RedirectRejectionHandlerSpec")
@Singleton
class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flux.create({emitter ->
            emitter.next(new UserDetails("sherlock", Collections.emptyList()))
            emitter.complete()
        }, FluxSink.OverflowStrategy.ERROR)
    }
}
