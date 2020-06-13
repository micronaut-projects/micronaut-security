package io.micronaut.security.endpoints


import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class LogoutControllerPathConfigurableSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LogoutControllerPathConfigurableSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.endpoints.logout.path': '/salir',
        ]
    }

    void "LogoutController is not accessible at /logout but at /salir"() {
        when:
        HttpRequest request = HttpRequest.POST("/logout", "").basicAuth("user", "password")
        client.exchange(request)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.FORBIDDEN

        when:
        request = HttpRequest.POST("/salir", "").basicAuth("user", "password")
        client.exchange(request)

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerPathConfigurableSpec')
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler {
        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            return HttpResponse.ok()
        }
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerPathConfigurableSpec')
    @Singleton
    static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create( {emitter ->
                emitter.onNext(AuthenticationResponse.build("user", new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
