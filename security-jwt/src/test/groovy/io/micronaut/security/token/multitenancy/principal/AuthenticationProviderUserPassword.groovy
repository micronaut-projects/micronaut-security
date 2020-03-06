package io.micronaut.security.token.multitenancy.principal

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'multitenancy.principal.gateway')
class AuthenticationProviderUserPassword implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        if ( authenticationRequest.identity == 'sherlock' && authenticationRequest.secret == 'elementary' ) {
            return Flowable.just(new UserDetails('sherlock', []))
        }
        if ( authenticationRequest.identity == 'watson' && authenticationRequest.secret == 'elementary' ) {
            return Flowable.just(new UserDetails('watson', []))
        }
        return Flowable.just(new AuthenticationFailed())
    }
}

