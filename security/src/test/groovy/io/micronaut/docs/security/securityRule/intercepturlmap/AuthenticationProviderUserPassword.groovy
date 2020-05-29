package io.micronaut.docs.security.securityRule.intercepturlmap

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationException
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
@Requires(property = 'spec.name', value = 'docsintercepturlmap')
class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flowable.create( {emitter ->
            if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                emitter.onNext(new UserDetails((String) authenticationRequest.identity, []))
            } else if ( authenticationRequest.identity == 'admin' && authenticationRequest.secret == 'password' ) {
                emitter.onNext(new UserDetails((String) authenticationRequest.identity, ['ROLE_ADMIN']))
            } else {
                emitter.onError(new AuthenticationException(new AuthenticationFailed()))
            }
            emitter.onComplete()
        }, BackpressureStrategy.ERROR)

    }
}
