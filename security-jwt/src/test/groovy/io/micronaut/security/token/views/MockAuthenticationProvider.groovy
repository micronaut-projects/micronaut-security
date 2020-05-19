package io.micronaut.security.token.views

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

@Requires(property = 'spec.name', value = 'SecurityViewModelProcessorSpec')
@Singleton
class MockAuthenticationProvider implements AuthenticationProvider {
    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flowable.create({emitter ->
            UserDetailsEmail userDetailsEmail = new UserDetailsEmail(authenticationRequest.identity as String, [], 'john@email.com')
            emitter.onNext(userDetailsEmail)
            emitter.onComplete()
        }, BackpressureStrategy.ERROR)
    }
}
