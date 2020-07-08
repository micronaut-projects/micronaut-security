package io.micronaut.security.token.multitenancy.principal

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'multitenancy.principal.gateway')
class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {

        Flowable.create({ emitter ->
            if ( authenticationRequest.getIdentity() == "sherlock" && authenticationRequest.getSecret() == "elementary") {
                emitter.onNext(new UserDetails('sherlock', []))
                emitter.onComplete()
            } else if ( authenticationRequest.getIdentity() == "watson" && authenticationRequest.getSecret() == "elementary") {
                emitter.onNext(new UserDetails('watson', []))
                emitter.onComplete()
            } else {
                emitter.onError(new AuthenticationException(new AuthenticationFailed()))
            }


        }, BackpressureStrategy.ERROR)
    }
}

