package io.micronaut.security.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MutableHttpResponse
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
import spock.lang.Ignore

import javax.inject.Singleton

class LogoutControllerAllowedMethodsGetSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LogoutControllerAllowedMethodsGetSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.logout.get-allowed': true
        ]
    }

    void "LogoutController can accept GET requests if micronaut.security.endpoints.logout.get-allowed=true"() {
        when:
        client.exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        noExceptionThrown()

        and:
        applicationContext.getBean(CustomLogoutHandler).invocations == 1
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsGetSpec')
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler {
        int invocations = 0
        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            invocations++
            return HttpResponse.ok()
        }
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsGetSpec')
    @Singleton
    static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create( { emitter ->
                emitter.onNext(AuthenticationResponse.build("user", new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)

        }
    }
}
