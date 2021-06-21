package io.micronaut.security.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.handlers.LogoutHandler
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Specification

import jakarta.inject.Singleton

class LogoutControllerAllowedMethodsSpec extends Specification {

    Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        m
    }

    String getSpecName() {
        'LogoutControllerAllowedMethodsSpec'
    }

    void "LogoutController does not accept GET requests by default"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration, Environment.TEST)
        RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.METHOD_NOT_ALLOWED

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "LogoutController can accept GET requests if micronaut.security.endpoints.logout.get-allowed=true"() {
        given:
        Map<String, Object> m = new HashMap<>()
        m.putAll(configuration)
        m.put('micronaut.security.endpoints.logout.get-allowed', true)

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m, Environment.TEST)
        RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        noExceptionThrown()

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "test logging out without credentials"() {
        given:
        Map<String, Object> m = new HashMap<>()
        m.putAll(configuration)
        m.put('micronaut.security.endpoints.logout.get-allowed', true)

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m, Environment.TEST)
        RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.POST('/logout', ""))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout"))

        then:
        noExceptionThrown()

        cleanup:
        client.close()
        embeddedServer.close()
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsSpec')
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler {
        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            return HttpResponse.ok()
        }
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsSpec')
    @Singleton
    static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                emitter.onNext(new UserDetails("user", []))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
