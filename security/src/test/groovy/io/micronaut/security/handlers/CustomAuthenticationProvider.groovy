package io.micronaut.security.handlers

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import javax.inject.Singleton

@Requires(property = "spec.name", value = "RedirectRejectionHandlerSpec")
@Singleton
class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        Flowable.create({emitter ->
            emitter.onNext(AuthenticationResponse.build("sherlock", new TokenConfiguration() {}))
            emitter.onComplete()
        }, BackpressureStrategy.ERROR)
    }
}
