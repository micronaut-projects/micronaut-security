package io.micronaut.security.token.multitenancy.principal

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Flux
import org.reactivestreams.Publisher

import jakarta.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'multitenancy.principal.gateway')
class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {

        Flux.create({ emitter ->
            if ( authenticationRequest.getIdentity() == "sherlock" && authenticationRequest.getSecret() == "elementary") {
                emitter.next(new UserDetails('sherlock', []))
                emitter.complete()
            } else if ( authenticationRequest.getIdentity() == "watson" && authenticationRequest.getSecret() == "elementary") {
                emitter.next(new UserDetails('watson', []))
                emitter.complete()
            } else {
                emitter.error(new AuthenticationException(new AuthenticationFailed()))
            }


        }, FluxSink.OverflowStrategy.ERROR)
    }
}

