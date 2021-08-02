package io.micronaut.docs.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Flux
import org.reactivestreams.Publisher

import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "securitysession")
@Singleton
class AuthenticationProviderUserPassword implements AuthenticationProvider  {
    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flux.create({ emitter ->
            if ( authenticationRequest.getIdentity() == "sherlock" && authenticationRequest.getSecret() == "password") {
                emitter.next(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
                emitter.complete()
            } else {
                emitter.error(new AuthenticationException(new AuthenticationFailed()))
            }

        }, FluxSink.OverflowStrategy.ERROR)
    }
}
