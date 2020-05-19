package io.micronaut.docs.security.securityRule.builtinendpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'docbuiltinendpoints')
class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flowable.create({emitter ->
            if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                emitter.onNext(new UserDetails('user', []))
                emitter.onComplete()
            } else {
                emitter.onNext(new AuthenticationFailed())
                emitter.onComplete()
            }
        }, BackpressureStrategy.ERROR)
    }
}
