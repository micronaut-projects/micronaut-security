package io.micronaut.security.token.views

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink

@Requires(property = 'spec.name', value = 'SecurityViewModelProcessorSpec')
@Singleton
class CustomAuthenticationProvider  implements AuthenticationProvider {
    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flux.create({ emitter ->
            UserDetailsEmail userDetailsEmail = new UserDetailsEmail(authenticationRequest.identity as String, [], 'john@email.com')
            emitter.next(userDetailsEmail)
            emitter.complete()
        }, FluxSink.OverflowStrategy.ERROR)
    }
}
