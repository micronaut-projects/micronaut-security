package io.micronaut.docs.security.session

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

@Requires(property = "spec.name", value = "securitysession")
@Singleton
class AuthenticationProviderUserPassword implements AuthenticationProvider  {
    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flowable.create({ emitter ->
            if ( authenticationRequest.getIdentity() == "sherlock" && authenticationRequest.getSecret() == "password") {
                emitter.onNext(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
            } else {
                emitter.onError(new AuthenticationException(new AuthenticationFailed()))
            }
            emitter.onComplete()
        }, BackpressureStrategy.ERROR)
    }
}
